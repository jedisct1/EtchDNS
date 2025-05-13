use crate::stats::{GlobalStats, SharedStats};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, server::conn::http1};
use hyper_util::rt::TokioIo;
use log::info;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Format a timestamp as an ISO 8601 string
fn format_timestamp(time: SystemTime) -> String {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            let millis = duration.subsec_millis();

            // Format as ISO 8601 (simplified)
            let seconds = secs % 60;
            let minutes = (secs / 60) % 60;
            let hours = (secs / 3600) % 24;
            let days = secs / 86400;

            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
                1970 + days / 365,     // Very simplified year calculation
                (days % 365) / 30 + 1, // Very simplified month calculation
                (days % 30) + 1,       // Very simplified day calculation
                hours,
                minutes,
                seconds,
                millis
            )
        }
        Err(_) => "invalid_time".to_string(),
    }
}

/// Format metrics as text
fn format_metrics(stats: &GlobalStats) -> String {
    let mut output = String::new();

    // Global metrics
    output.push_str("# HELP etchdns_total_queries Total number of DNS queries processed\n");
    output.push_str("# TYPE etchdns_total_queries counter\n");
    output.push_str(&format!("etchdns_total_queries {}\n", stats.total_queries));

    output.push_str("# HELP etchdns_successful_queries Total number of successful DNS queries\n");
    output.push_str("# TYPE etchdns_successful_queries counter\n");
    output.push_str(&format!(
        "etchdns_successful_queries {}\n",
        stats.total_successful
    ));

    output.push_str("# HELP etchdns_failed_queries Total number of failed DNS queries\n");
    output.push_str("# TYPE etchdns_failed_queries counter\n");
    output.push_str(&format!("etchdns_failed_queries {}\n", stats.total_failed));

    output.push_str("# HELP etchdns_timeout_queries Total number of timed out DNS queries\n");
    output.push_str("# TYPE etchdns_timeout_queries counter\n");
    output.push_str(&format!(
        "etchdns_timeout_queries {}\n",
        stats.total_timeouts
    ));

    // Per-resolver metrics
    output.push_str("# HELP etchdns_resolver_response_time_ms Average response time in milliseconds per resolver\n");
    output.push_str("# TYPE etchdns_resolver_response_time_ms gauge\n");

    output.push_str(
        "# HELP etchdns_resolver_success_count Number of successful queries per resolver\n",
    );
    output.push_str("# TYPE etchdns_resolver_success_count counter\n");

    output
        .push_str("# HELP etchdns_resolver_failure_count Number of failed queries per resolver\n");
    output.push_str("# TYPE etchdns_resolver_failure_count counter\n");

    output.push_str(
        "# HELP etchdns_resolver_timeout_count Number of timed out queries per resolver\n",
    );
    output.push_str("# TYPE etchdns_resolver_timeout_count counter\n");

    output.push_str("# HELP etchdns_resolver_last_used_timestamp Last time the resolver was used (Unix timestamp)\n");
    output.push_str("# TYPE etchdns_resolver_last_used_timestamp gauge\n");

    // Add metrics for each resolver
    for (addr, stats) in &stats.resolver_stats {
        let addr_str = addr.to_string().replace(':', "_");

        output.push_str(&format!(
            "etchdns_resolver_response_time_ms{{resolver=\"{}\"}} {:.3}\n",
            addr_str, stats.avg_response_time_ms
        ));

        output.push_str(&format!(
            "etchdns_resolver_success_count{{resolver=\"{}\"}} {}\n",
            addr_str, stats.success_count
        ));

        output.push_str(&format!(
            "etchdns_resolver_failure_count{{resolver=\"{}\"}} {}\n",
            addr_str, stats.failure_count
        ));

        output.push_str(&format!(
            "etchdns_resolver_timeout_count{{resolver=\"{}\"}} {}\n",
            addr_str, stats.timeout_count
        ));

        // Format the last_used timestamp
        let timestamp = format_timestamp(stats.last_used);
        output.push_str(&format!(
            "etchdns_resolver_last_used_timestamp{{resolver=\"{}\", time=\"{}\"}} {}\n",
            addr_str,
            timestamp,
            match stats.last_used.duration_since(UNIX_EPOCH) {
                Ok(duration) => duration.as_secs(),
                Err(_) => 0,
            }
        ));
    }

    output
}

/// Handle HTTP requests
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    stats: Arc<SharedStats>,
    metrics_path: String,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();

    if path == metrics_path {
        // Get the current stats
        let current_stats = stats.get_stats().await;

        // Format the metrics
        let metrics_text = format_metrics(&current_stats);

        // Return the metrics
        Ok(Response::new(Full::new(Bytes::from(metrics_text))))
    } else {
        // Return 404 for any other path
        let mut response = Response::new(Full::new(Bytes::from("Not Found")));
        *response.status_mut() = StatusCode::NOT_FOUND;
        Ok(response)
    }
}

/// Start the HTTP metrics server
pub async fn start_metrics_server(
    addr: SocketAddr,
    metrics_path: String,
    stats: Arc<SharedStats>,
    max_connections: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create a TCP listener
    let listener = TcpListener::bind(addr).await?;
    info!(
        "Metrics server listening on {}, path: {}",
        addr, metrics_path
    );

    // Create a semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(max_connections));

    // Accept connections
    loop {
        // Accept a connection
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        // Clone the stats and metrics path for this connection
        let stats = stats.clone();
        let metrics_path = metrics_path.clone();
        let semaphore = semaphore.clone();

        // Spawn a task to handle the connection
        tokio::spawn(async move {
            // Try to acquire a permit from the semaphore
            let _permit = match semaphore.try_acquire() {
                Ok(permit) => permit,
                Err(_) => {
                    // Too many connections, reject this one
                    return;
                }
            };

            // Handle the connection
            let service = hyper::service::service_fn(move |req| {
                let stats = stats.clone();
                let metrics_path = metrics_path.clone();
                async move { handle_request(req, stats, metrics_path).await }
            });

            // Process the connection
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                // Log any errors
                log::error!("Error serving connection: {}", err);
            }
        });
    }
}
