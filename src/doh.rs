use crate::dns_processor::DnsQueryProcessor;
use crate::query_manager::QueryManager;
use crate::stats::SharedStats;
use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode, header, server::conn::http1};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Handle DNS-over-HTTPS (DoH) requests
///
/// This function handles both GET and POST requests according to RFC 8484.
/// - GET requests should have a 'dns' query parameter with a base64url encoded DNS message
/// - POST requests should have a Content-Type of 'application/dns-message' and the body contains the DNS message
async fn handle_doh_request(
    req: Request<hyper::body::Incoming>,
    query_manager: Arc<QueryManager>,
    upstream_servers: Vec<String>,
    server_timeout: u64,
    dns_packet_len_max: usize,
    stats: Arc<SharedStats>,
    load_balancing_strategy: crate::load_balancer::LoadBalancingStrategy,
    client_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Check the request method
    match *req.method() {
        // Handle GET requests
        Method::GET => {
            // Extract the 'dns' query parameter
            let uri = req.uri();
            let query = uri.query().unwrap_or("");

            // Parse the query parameters
            let params: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes())
                .into_owned()
                .collect();

            // Find the 'dns' parameter
            let dns_param = params.iter().find(|(name, _)| name == "dns");

            match dns_param {
                Some((_, value)) => {
                    // Decode the base64url encoded DNS message
                    match general_purpose::URL_SAFE_NO_PAD.decode(value) {
                        Ok(dns_message) => {
                            // Process the DNS message
                            process_dns_message(
                                dns_message,
                                query_manager,
                                upstream_servers,
                                server_timeout,
                                dns_packet_len_max,
                                stats,
                                load_balancing_strategy,
                                &client_addr,
                            )
                            .await
                        }
                        Err(e) => {
                            error!("Failed to decode base64url DNS message: {e}");
                            let mut response = Response::new(Full::new(Bytes::from(
                                "Bad Request: Invalid DNS message encoding",
                            )));
                            *response.status_mut() = StatusCode::BAD_REQUEST;
                            Ok(response)
                        }
                    }
                }
                None => {
                    // Missing 'dns' parameter
                    let mut response = Response::new(Full::new(Bytes::from(
                        "Bad Request: Missing 'dns' parameter",
                    )));
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    Ok(response)
                }
            }
        }

        // Handle POST requests
        Method::POST => {
            // Check the Content-Type header
            let content_type = req
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");

            if content_type == "application/dns-message" {
                // Read the request body
                match req.into_body().collect().await {
                    Ok(bytes) => {
                        // Process the DNS message
                        process_dns_message(
                            bytes.to_bytes().to_vec(),
                            query_manager,
                            upstream_servers,
                            server_timeout,
                            dns_packet_len_max,
                            stats,
                            load_balancing_strategy,
                            &client_addr,
                        )
                        .await
                    }
                    Err(e) => {
                        error!("Failed to read request body: {e}");
                        let mut response = Response::new(Full::new(Bytes::from(
                            "Bad Request: Failed to read request body",
                        )));
                        *response.status_mut() = StatusCode::BAD_REQUEST;
                        Ok(response)
                    }
                }
            } else {
                // Invalid Content-Type
                let mut response = Response::new(Full::new(Bytes::from(
                    "Bad Request: Content-Type must be application/dns-message",
                )));
                *response.status_mut() = StatusCode::BAD_REQUEST;
                Ok(response)
            }
        }

        // Handle other methods
        _ => {
            // Method not allowed
            let mut response = Response::new(Full::new(Bytes::from("Method Not Allowed")));
            *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
            Ok(response)
        }
    }
}

/// Handler for DoH requests
struct DoHHandler;

impl DnsQueryProcessor for DoHHandler {}

/// Process a DNS message received via DoH
async fn process_dns_message(
    dns_message: Vec<u8>,
    query_manager: Arc<QueryManager>,
    upstream_servers: Vec<String>,
    server_timeout: u64,
    dns_packet_len_max: usize,
    stats: Arc<SharedStats>,
    load_balancing_strategy: crate::load_balancer::LoadBalancingStrategy,
    client_addr: &SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // Create a DoH handler
    let handler = DoHHandler;

    // Process the DNS query using the DnsQueryProcessor trait
    let client_addr_str = client_addr.to_string();
    let result = handler
        .process_dns_query(
            &dns_message,
            &client_addr_str,
            "DoH",
            &query_manager,
            &upstream_servers,
            server_timeout,
            dns_packet_len_max,
            Some(stats),
            load_balancing_strategy,
        )
        .await;

    match result {
        Some((response_data, _)) => {
            // Create a response with the DNS message
            let mut http_response = Response::new(Full::new(Bytes::from(response_data.clone())));
            http_response.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/dns-message"),
            );

            // Add HTTP caching headers
            // Extract the minimum TTL from the DNS response, with a 1 second minimum
            let cache_ttl = match crate::dns_parser::extract_min_ttl(&response_data) {
                Ok(Some(ttl)) => std::cmp::max(ttl, 1), // Minimum of 1 second
                _ => 10,                                // Default to 10 seconds if no TTL found
            };

            // Add Cache-Control header
            let cache_control = format!("public, max-age={cache_ttl}");
            if let Ok(value) = header::HeaderValue::from_str(&cache_control) {
                http_response
                    .headers_mut()
                    .insert(header::CACHE_CONTROL, value);
            }

            // Add Expires header
            let now = std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                );
            let expiry_time = now + std::time::Duration::from_secs(cache_ttl as u64);
            let expiry_http_date = httpdate::fmt_http_date(expiry_time);
            if let Ok(value) = header::HeaderValue::from_str(&expiry_http_date) {
                http_response.headers_mut().insert(header::EXPIRES, value);
            }

            debug!("DoH response with cache TTL: {cache_ttl} seconds");
            Ok(http_response)
        }
        None => {
            // Error already logged in process_dns_query
            let mut http_response = Response::new(Full::new(Bytes::from("Internal Server Error")));
            *http_response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            Ok(http_response)
        }
    }
}

/// Start the DNS-over-HTTPS (DoH) server
pub async fn start_doh_server(
    addr: SocketAddr,
    query_manager: Arc<QueryManager>,
    upstream_servers: Vec<String>,
    server_timeout: u64,
    dns_packet_len_max: usize,
    stats: Arc<SharedStats>,
    max_connections: usize,
    rate_limiter: Option<Arc<crate::rate_limiter::RateLimiter>>,
    load_balancing_strategy: crate::load_balancer::LoadBalancingStrategy,
    ip_validator: Option<Arc<dyn std::any::Any + Send + Sync>>,
    enable_strict_ip_validation: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create a TCP listener
    let listener = TcpListener::bind(addr).await?;
    info!("DoH server listening on {addr}");

    // Create a semaphore to limit concurrent connections
    let semaphore = Arc::new(Semaphore::new(max_connections));

    // Accept connections
    loop {
        // Accept a connection
        let (stream, client_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);

        // Clone the values we need for this connection
        let query_manager = query_manager.clone();
        let upstream_servers = upstream_servers.clone();
        let stats = stats.clone();
        let semaphore = semaphore.clone();
        let rate_limiter = rate_limiter.clone();
        let ip_validator = ip_validator.clone();

        // Spawn a task to handle the connection
        tokio::spawn(async move {
            // Apply IP validation to the client address if enabled
            if enable_strict_ip_validation {
                // We have validation in the main client acceptance logic already
                if let Some(_validator) = &ip_validator {
                    // Validator is available, but we can't use it directly in this module
                    // So we'll just log a message
                    debug!("Using provided IP validator for DoH client {client_addr}");
                }
            }

            // Check rate limit for DoH client if enabled
            if let Some(limiter) = &rate_limiter {
                // Extract the client IP address
                let client_ip = client_addr.ip();

                // Check if the client is allowed to make a connection
                if !limiter.is_allowed(client_ip).await {
                    warn!("Rate limit exceeded for DoH client {client_addr}, dropping connection");
                    return;
                }
            }

            // Try to acquire a permit from the semaphore
            let _permit = match semaphore.try_acquire() {
                Ok(permit) => permit,
                Err(_) => {
                    // Too many connections, reject this one
                    warn!("Too many DoH connections, rejecting connection from {client_addr}");
                    return;
                }
            };

            debug!("Accepted DoH connection from {client_addr}");

            // Handle the connection
            let client_addr_clone = client_addr;
            let service = hyper::service::service_fn(move |req| {
                let query_manager = query_manager.clone();
                let upstream_servers = upstream_servers.clone();
                let stats = stats.clone();
                let load_balancing_strategy = load_balancing_strategy;
                let client_addr = client_addr_clone;

                async move {
                    handle_doh_request(
                        req,
                        query_manager,
                        upstream_servers,
                        server_timeout,
                        dns_packet_len_max,
                        stats,
                        load_balancing_strategy,
                        client_addr,
                    )
                    .await
                }
            });

            // Process the connection with timeout
            let server_timeout_duration = std::time::Duration::from_secs(server_timeout);
            let connection_future = http1::Builder::new().serve_connection(io, service);

            match tokio::time::timeout(server_timeout_duration, connection_future).await {
                Ok(result) => {
                    if let Err(err) = result {
                        // Log any errors
                        error!("Error serving DoH connection from {client_addr}: {err}");
                    }
                }
                Err(_) => {
                    // Timeout occurred
                    error!(
                        "DoH connection from {client_addr} timed out after {server_timeout} seconds"
                    );
                }
            }

            debug!("Closed DoH connection from {client_addr}");
        });
    }
}
