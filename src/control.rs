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

/// Cache status response structure
#[derive(Serialize, Deserialize)]
struct CacheStatusResponse {
    success: bool,
    size: usize,
    capacity: usize,
    hit_rate: f64,
    hits: u64,
    misses: u64,
}

/// Check if a domain is within a zone
///
/// For example, if zone is "example.com", then "www.example.com" is within that zone,
/// but "example.org" is not.
fn is_domain_in_zone(domain: &str, zone: &str) -> bool {
    // Normalize both domain and zone (lowercase, no trailing dot)
    let normalized_domain = domain.to_lowercase();
    let normalized_zone = zone.to_lowercase();

    // Check if domain equals zone
    if normalized_domain == normalized_zone {
        return true;
    }

    // Check if domain is a subdomain of zone
    // Domain must end with .zone
    normalized_domain.ends_with(&format!(".{normalized_zone}"))
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
                error!("Failed to serialize API response: {e}");
                r#"{"success":false,"message":"Internal server error"}"#.to_string()
            });

            let mut response = Response::new(Full::new(Bytes::from(json)));
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
            Ok(response)
        }

        // GET /cache - Return cache status
        (&Method::GET, "cache") => {
            if let Some(cache) = dns_cache {
                // Get cache size and capacity
                let size = cache.len();
                let capacity = cache.capacity();

                // Get cache hit/miss statistics from the stats system
                // These would need to be passed in from the main application
                // For now, we'll just use placeholder values
                let hits = 0;
                let misses = 0;
                let hit_rate = if hits + misses > 0 {
                    hits as f64 / (hits + misses) as f64
                } else {
                    0.0
                };

                let response = CacheStatusResponse {
                    success: true,
                    size,
                    capacity,
                    hit_rate,
                    hits,
                    misses,
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
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
                    error!("Failed to serialize API response: {e}");
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

        // DELETE /cache - Clear the DNS cache
        (&Method::DELETE, "cache") => {
            if let Some(cache) = dns_cache {
                // Clear the cache
                cache.clear();

                let cache_size = cache.len();
                info!("DNS cache cleared, current size: {cache_size}");

                let response = ApiResponse {
                    success: true,
                    message: format!("Cache cleared successfully. Current size: {cache_size}"),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
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
                    error!("Failed to serialize API response: {e}");
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

        // DELETE /cache/zone/<zone> - Clear entries for a specific zone
        (&Method::DELETE, zone_path) if zone_path.starts_with("cache/zone/") => {
            if let Some(cache) = dns_cache {
                // Extract the zone from the path
                let zone = zone_path.strip_prefix("cache/zone/").unwrap_or("");
                if zone.is_empty() {
                    let response = ApiResponse {
                        success: false,
                        message: "Zone parameter is required".to_string(),
                    };
                    let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                        error!("Failed to serialize API response: {e}");
                        r#"{"success":false,"message":"Internal server error"}"#.to_string()
                    });

                    let mut response = Response::new(Full::new(Bytes::from(json)));
                    response.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }

                // Get the initial cache size
                let initial_size = cache.len();

                // Use retain to keep only entries that are NOT in the specified zone
                cache.retain(|key, _| !is_domain_in_zone(&key.name, zone));

                // Get the new cache size
                let new_size = cache.len();
                let removed_entries = initial_size - new_size;

                info!("Cleared {removed_entries} entries for zone {zone} from DNS cache");

                let response = ApiResponse {
                    success: true,
                    message: format!(
                        "Cleared {removed_entries} entries for zone {zone} from DNS cache. New size: {new_size}"
                    ),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
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
                    error!("Failed to serialize API response: {e}");
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

        // DELETE /cache/name/<name> - Clear a specific entry
        (&Method::DELETE, name_path) if name_path.starts_with("cache/name/") => {
            if let Some(cache) = dns_cache {
                // Extract the name from the path
                let name = name_path.strip_prefix("cache/name/").unwrap_or("");
                if name.is_empty() {
                    let response = ApiResponse {
                        success: false,
                        message: "Name parameter is required".to_string(),
                    };
                    let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                        error!("Failed to serialize API response: {e}");
                        r#"{"success":false,"message":"Internal server error"}"#.to_string()
                    });

                    let mut response = Response::new(Full::new(Bytes::from(json)));
                    response.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("application/json"),
                    );
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(response);
                }

                // Get the initial cache size
                let initial_size = cache.len();

                // Use retain to keep only entries that don't match the specified name
                // We need to normalize the name for comparison
                let normalized_name = crate::dns_key::DNSKey::normalize_name(name);
                cache.retain(|key, _| key.name != normalized_name);

                // Get the new cache size
                let new_size = cache.len();
                let removed_entries = initial_size - new_size;

                info!("Cleared {removed_entries} entries for name {name} from DNS cache");

                let response = ApiResponse {
                    success: true,
                    message: format!(
                        "Cleared {removed_entries} entries for name {name} from DNS cache. New size: {new_size}"
                    ),
                };
                let json = serde_json::to_string(&response).unwrap_or_else(|e| {
                    error!("Failed to serialize API response: {e}");
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
                    error!("Failed to serialize API response: {e}");
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
    info!("Control server listening on {addr}, base path: {control_path}");

    if dns_cache.is_some() {
        info!(
            "DNS cache control API enabled at {control_path}/cache (GET/DELETE), {control_path}/cache/zone/<zone> (DELETE), and {control_path}/cache/name/<name> (DELETE)"
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
                    warn!("Too many control connections, rejecting connection from {client_addr}");
                    return;
                }
            };

            debug!("Accepted control connection from {client_addr}");

            // Handle the connection
            let service = hyper::service::service_fn(move |req| {
                let control_path = control_path.clone();
                let dns_cache = dns_cache.clone();
                async move { handle_request(req, control_path, dns_cache).await }
            });

            // Process the connection
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                // Log any errors
                error!("Error serving control connection from {client_addr}: {err}");
            }

            debug!("Closed control connection from {client_addr}");
        });
    }
}
