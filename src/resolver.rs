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
    move |data: Vec<u8>| {
        // Create a new client query with stats if available
        let client_query = match stats.clone() {
            Some(stats) => ClientQuery::new(
                data,
                upstream_servers.clone(),
                server_timeout,
                dns_packet_len_max,
                stats,
                load_balancing_strategy,
            ),
            None => {
                // This should not happen in normal operation
                warn!("No stats available for resolver function");
                // Create a dummy query without stats

                ClientQuery {
                    data,
                    upstream_servers: upstream_servers.clone(),
                    server_timeout,
                    dns_packet_len_max,
                    max_udp_response_size: dns_parser::DNS_MAX_UDP_PACKET_SIZE,
                    stats: None,
                    load_balancing_strategy,
                }
            }
        };
        Box::pin(async move {
            match client_query.process().await {
                Ok(data) => Ok(data),
                Err(e) => Err(DnsError::UpstreamError(format!("Error: {}", e))),
            }
        }) as BoxFuture<'static, _>
    }
}
