use futures::future::BoxFuture;
use log::warn;

use crate::ClientQuery;
use crate::dns_parser;
use crate::errors::{DnsError, DnsResult};
use crate::load_balancer::LoadBalancingStrategy;
use crate::stats::SharedStats;

use std::sync::Arc;

/// Creates a resolver function for DNS queries
///
/// This function creates a resolver function that can be used to resolve DNS queries.
/// It encapsulates the common logic for creating a resolver function across different client types.
///
/// # Arguments
///
/// * `upstream_servers` - The upstream DNS servers to forward queries to
/// * `server_timeout` - The timeout for upstream server connections in seconds
/// * `dns_packet_len_max` - The maximum DNS packet size
/// * `stats` - The global statistics tracker
/// * `load_balancing_strategy` - The load balancing strategy to use
///
/// # Returns
///
/// A function that takes a DNS query and returns a future that resolves to a DNS response
pub fn create_resolver(
    upstream_servers: Vec<String>,
    server_timeout: u64,
    dns_packet_len_max: usize,
    stats: Option<Arc<SharedStats>>,
    load_balancing_strategy: LoadBalancingStrategy,
) -> impl Fn(Vec<u8>) -> BoxFuture<'static, DnsResult<Vec<u8>>> + Send + Sync + 'static {
    // Call the internal implementation with default ECS settings (disabled)
    create_resolver_with_client_ip(
        upstream_servers,
        server_timeout,
        dns_packet_len_max,
        stats,
        load_balancing_strategy,
        String::new(),
        false,
        24,
        56,
    )
}

/// Creates a resolver function for DNS queries with EDNS-client-subnet support
///
/// This function creates a resolver function that can be used to resolve DNS queries,
/// with optional EDNS-client-subnet support to include client IP information in the query.
///
/// # Arguments
///
/// * `upstream_servers` - The upstream DNS servers to forward queries to
/// * `server_timeout` - The timeout for upstream server connections in seconds
/// * `dns_packet_len_max` - The maximum DNS packet size
/// * `stats` - The global statistics tracker
/// * `load_balancing_strategy` - The load balancing strategy to use
/// * `client_ip` - The client IP address for EDNS-client-subnet
/// * `enable_ecs` - Whether to enable EDNS-client-subnet
/// * `ecs_prefix_v4` - IPv4 prefix length for EDNS-client-subnet
/// * `ecs_prefix_v6` - IPv6 prefix length for EDNS-client-subnet
///
/// # Returns
///
/// A function that takes a DNS query and returns a future that resolves to a DNS response
pub fn create_resolver_with_client_ip(
    upstream_servers: Vec<String>,
    server_timeout: u64,
    dns_packet_len_max: usize,
    stats: Option<Arc<SharedStats>>,
    load_balancing_strategy: LoadBalancingStrategy,
    client_ip: String,
    enable_ecs: bool,
    ecs_prefix_v4: u8,
    ecs_prefix_v6: u8,
) -> impl Fn(Vec<u8>) -> BoxFuture<'static, DnsResult<Vec<u8>>> + Send + Sync + 'static {
    // Create Arc wrappers outside the closure to avoid cloning on each call
    let upstream_servers_arc = Arc::new(upstream_servers);
    let stats_arc = stats.map(|s| Arc::clone(&s));

    // Clone the client IP and ECS settings to be captured by the closure
    let client_ip_clone = client_ip.clone();
    let enable_ecs_clone = enable_ecs;
    let ecs_prefix_v4_clone = ecs_prefix_v4;
    let ecs_prefix_v6_clone = ecs_prefix_v6;

    move |data: Vec<u8>| {
        // Clone the Arc, not the inner data
        let upstream_servers_ref = Arc::clone(&upstream_servers_arc);

        // Create a new client query with stats if available
        let client_query = match &stats_arc {
            Some(stats) => {
                if enable_ecs_clone && !client_ip_clone.is_empty() {
                    // Create a client query with ECS support
                    ClientQuery::new_with_client_ip(
                        data,
                        (*upstream_servers_ref).clone(),
                        server_timeout,
                        dns_packet_len_max,
                        Arc::clone(stats),
                        load_balancing_strategy,
                        client_ip_clone.clone(),
                        enable_ecs_clone,
                        ecs_prefix_v4_clone,
                        ecs_prefix_v6_clone,
                    )
                } else {
                    // Create a regular client query without ECS
                    ClientQuery::new(
                        data,
                        (*upstream_servers_ref).clone(),
                        server_timeout,
                        dns_packet_len_max,
                        Arc::clone(stats),
                        load_balancing_strategy,
                    )
                }
            }
            None => {
                // This should not happen in normal operation
                warn!("No stats available for resolver function");
                // Create a dummy query without stats
                ClientQuery {
                    data,
                    upstream_servers: (*upstream_servers_ref).clone(),
                    server_timeout,
                    dns_packet_len_max,
                    max_udp_response_size: dns_parser::DNS_MAX_UDP_PACKET_SIZE,
                    stats: None,
                    load_balancing_strategy,
                    client_ip: if enable_ecs_clone && !client_ip_clone.is_empty() {
                        Some(client_ip_clone.clone())
                    } else {
                        None
                    },
                    enable_ecs: enable_ecs_clone,
                    ecs_prefix_v4: ecs_prefix_v4_clone,
                    ecs_prefix_v6: ecs_prefix_v6_clone,
                }
            }
        };

        Box::pin(async move {
            match client_query.process().await {
                Ok(data) => Ok(data),
                Err(e) => Err(DnsError::UpstreamError(format!("Error: {e}"))),
            }
        }) as BoxFuture<'static, _>
    }
}
