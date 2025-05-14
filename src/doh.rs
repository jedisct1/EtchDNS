use crate::dns_processor;
use crate::query_manager_new::QueryManager;
use crate::resolver;
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
                            error!("Failed to decode base64url DNS message: {}", e);
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
                        error!("Failed to read request body: {}", e);
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
    // Validate the packet and create a DNSKey
    let dns_key = match dns_processor::validate_and_create_key(&dns_message, "DoH client") {
        Ok(key) => key,
        Err(_) => {
            // Error already logged in validate_and_create_key
            let mut response =
                Response::new(Full::new(Bytes::from("Bad Request: Invalid DNS packet")));
            *response.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(response);
        }
    };

    // Create a resolver function for this query
    let query_data = dns_message.clone();
    let resolver = resolver::create_resolver(
        upstream_servers,
        server_timeout,
        dns_packet_len_max,
        Some(stats),
        load_balancing_strategy,
    );

    // Submit the query to the query manager with client address
    match query_manager
        .submit_query_with_client(dns_key, query_data, resolver, &client_addr.to_string())
        .await
    {
        Ok(mut receiver) => {
            // Wait for the response
            match receiver.recv().await {
                Ok(response) => {
                    // Check if the response contains an error
                    if let Some(error_msg) = response.error {
                        // Log the error
                        error!("Error in DNS response: {}", error_msg);
                        let mut http_response =
                            Response::new(Full::new(Bytes::from("Internal Server Error")));
                        *http_response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        return Ok(http_response);
                    }

                    // Create a response with the DNS message
                    let mut http_response = Response::new(Full::new(Bytes::from(response.data)));
                    http_response.headers_mut().insert(
                        header::CONTENT_TYPE,
                        header::HeaderValue::from_static("application/dns-message"),
                    );
                    Ok(http_response)
                }
                Err(e) => {
                    error!("Failed to receive response from query manager: {}", e);
                    let mut http_response =
                        Response::new(Full::new(Bytes::from("Internal Server Error")));
                    *http_response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    Ok(http_response)
                }
            }
        }
        Err(e) => {
            error!("Failed to submit query to query manager: {}", e);
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create a TCP listener
    let listener = TcpListener::bind(addr).await?;
    info!("DoH server listening on {}", addr);

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

        // Spawn a task to handle the connection
        tokio::spawn(async move {
            // Check rate limit for DoH client if enabled
            if let Some(limiter) = &rate_limiter {
                // Extract the client IP address
                let client_ip = client_addr.ip();

                // Check if the client is allowed to make a connection
                if !limiter.is_allowed(client_ip).await {
                    warn!(
                        "Rate limit exceeded for DoH client {}, dropping connection",
                        client_addr
                    );
                    return;
                }
            }

            // Try to acquire a permit from the semaphore
            let _permit = match semaphore.try_acquire() {
                Ok(permit) => permit,
                Err(_) => {
                    // Too many connections, reject this one
                    warn!(
                        "Too many DoH connections, rejecting connection from {}",
                        client_addr
                    );
                    return;
                }
            };

            debug!("Accepted DoH connection from {}", client_addr);

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
                        error!("Error serving DoH connection from {}: {}", client_addr, err);
                    }
                }
                Err(_) => {
                    // Timeout occurred
                    error!(
                        "DoH connection from {} timed out after {} seconds",
                        client_addr, server_timeout
                    );
                }
            }

            debug!("Closed DoH connection from {}", client_addr);
        });
    }
}
