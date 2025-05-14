use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, server::conn::http1};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::cache::SyncDnsCache;

/// Response structure for API calls
#[derive(Serialize, Deserialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

/// Handle HTTP requests for the control API
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    control_path: String,
    dns_cache: Option<Arc<SyncDnsCache>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let method = req.method();

    // Check if the path starts with the control path
    if !path.starts_with(&control_path) {
        // Return 404 for any path not starting with control_path
        let mut response = Response::new(Full::new(Bytes::from("Not Found")));
        *response.status_mut() = StatusCode::NOT_FOUND;
        return Ok(response);
    }

    // Remove the control_path prefix to get the actual endpoint
    let endpoint = path
        .strip_prefix(&control_path)
        .unwrap_or("")
        .trim_start_matches('/');

    match (method, endpoint) {
        // GET /status - Return server status
        (&Method::GET, "status") => {
            let response = ApiResponse {
                success: true,
                message: "Server is running".to_string(),
            };
            let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                error!("Failed to serialize API response: {}", e);
                r#"{"success":false,"message":"Internal server error"}"#.to_string()
            });

            let mut response = Response::new(Full::new(Bytes::from(json)));
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            Ok(response)
        }

        // POST /cache/clear - Clear the DNS cache
        (&Method::POST, "cache/clear") => {
            if let Some(cache) = dns_cache {
                // Clear the cache
                cache.clear();

                let cache_size = cache.len();
                info!("DNS cache cleared, current size: {}", cache_size);

                let response = ApiResponse {
                    success: true,
                    message: format!("Cache cleared successfully. Current size: {}", cache_size),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {}", e);
                    r#"{"success":false,"message":"Internal server error"}"#.to_string()
                });

                let mut response = Response::new(Full::new(Bytes::from(json)));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                Ok(response)
            } else {
                // DNS cache not available
                let response = ApiResponse {
                    success: false,
                    message: "DNS cache not available".to_string(),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {}", e);
                    r#"{"success":false,"message":"Internal server error"}"#.to_string()
                });

                let mut response = Response::new(Full::new(Bytes::from(json)));
                response.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static("application/json"),
                );
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                Ok(response)
            }
        }

        // Any other endpoint
        _ => {
            let response = ApiResponse {
                success: false,
                message: "Endpoint not found".to_string(),
            };
            let json = serde_json::to_string(&response).unwrap();

            let mut response = Response::new(Full::new(Bytes::from(json)));
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            *response.status_mut() = StatusCode::NOT_FOUND;
            Ok(response)
        }
    }
}

/// Start the HTTP control server
pub async fn start_control_server(
    addr: SocketAddr,
    control_path: String,
    max_connections: usize,
    dns_cache: Option<Arc<SyncDnsCache>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create a TCP listener
    let listener = TcpListener::bind(addr).await?;
    info!(
        "Control server listening on {}, base path: {}",
        addr, control_path
    );

    if dns_cache.is_some() {
        info!(
            "DNS cache control API enabled at {}/cache/clear",
            control_path
        );
    } else {
        warn!("DNS cache not available for control API");
    }

    // Create a semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(max_connections));

    // Accept connections
    loop {
        // Accept a connection
        let (stream, client_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);

        // Clone the resources for this connection
        let control_path = control_path.clone();
        let semaphore = semaphore.clone();
        let dns_cache = dns_cache.clone();

        // Spawn a task to handle the connection
        tokio::spawn(async move {
            // Try to acquire a permit from the semaphore
            let _permit = match semaphore.try_acquire() {
                Ok(permit) => permit,
                Err(_) => {
                    // Too many connections, reject this one
                    warn!(
                        "Too many control connections, rejecting connection from {}",
                        client_addr
                    );
                    return;
                }
            };

            debug!("Accepted control connection from {}", client_addr);

            // Handle the connection
            let service = hyper::service::service_fn(move |req| {
                let control_path = control_path.clone();
                let dns_cache = dns_cache.clone();
                async move { handle_request(req, control_path, dns_cache).await }
            });

            // Process the connection
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                // Log any errors
                error!(
                    "Error serving control connection from {}: {}",
                    client_addr, err
                );
            }

            debug!("Closed control connection from {}", client_addr);
        });
    }
}
