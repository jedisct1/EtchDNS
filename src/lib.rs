// Export modules that need to be accessible from fuzzing tests
pub mod allowed_zones;
pub mod cache;
pub mod control;
pub mod dns_key;
pub mod dns_parser;
pub mod dns_processor;
pub mod doh;
pub mod errors;
pub mod hooks;
pub mod ip_validator;
pub mod load_balancer;
pub mod metrics;
pub mod nx_zones;
pub mod probe;
pub mod query_logger;
pub mod query_manager;
pub mod rate_limiter;
pub mod resolver;
pub mod stats;

// Re-export error types for convenience
pub use errors::{DnsError, EtchDnsError, EtchDnsResult};

// Re-export the ClientQuery struct for use in resolver.rs
use load_balancer::LoadBalancingStrategy;
use stats::SharedStats;
use std::sync::Arc;

/// Structure to handle client queries
#[derive(Clone)]
pub struct ClientQuery {
    /// The data received from the client
    pub data: Vec<u8>,
    /// The upstream servers to forward the query to
    pub upstream_servers: Vec<String>,
    /// The server timeout in seconds
    pub server_timeout: u64,
    /// The maximum DNS packet size
    pub dns_packet_len_max: usize,
    /// The maximum UDP response size for this client
    pub max_udp_response_size: usize,
    /// Global statistics tracker
    pub stats: Option<Arc<SharedStats>>,
    /// Load balancing strategy
    pub load_balancing_strategy: LoadBalancingStrategy,
    /// Client IP address for EDNS-client-subnet
    pub client_ip: Option<String>,
    /// Whether EDNS-client-subnet is enabled
    pub enable_ecs: bool,
    /// IPv4 prefix length for EDNS-client-subnet
    pub ecs_prefix_v4: u8,
    /// IPv6 prefix length for EDNS-client-subnet
    pub ecs_prefix_v6: u8,
    /// Whether spoof protection is enabled
    pub spoof_protection: bool,
}

impl ClientQuery {
    /// Create a new ClientQuery with statistics tracking
    pub fn new(
        data: Vec<u8>,
        upstream_servers: Vec<String>,
        server_timeout: u64,
        dns_packet_len_max: usize,
        stats: Arc<SharedStats>,
        load_balancing_strategy: LoadBalancingStrategy,
    ) -> Self {
        // Extract the EDNS0 maximum datagram size from the query, if present
        let max_udp_response_size = match dns_parser::extract_edns0_max_size(&data) {
            Ok(Some(size)) => size as usize,
            _ => dns_parser::DNS_MAX_UDP_PACKET_SIZE,
        };

        Self {
            data,
            upstream_servers,
            server_timeout,
            dns_packet_len_max,
            max_udp_response_size,
            stats: Some(stats),
            load_balancing_strategy,
            client_ip: None,
            enable_ecs: false,
            ecs_prefix_v4: 24,      // Default IPv4 prefix length
            ecs_prefix_v6: 56,      // Default IPv6 prefix length
            spoof_protection: true, // Default to enabled for security
        }
    }

    /// Create a new ClientQuery with statistics tracking and client IP for EDNS-client-subnet
    pub fn new_with_client_ip(
        data: Vec<u8>,
        upstream_servers: Vec<String>,
        server_timeout: u64,
        dns_packet_len_max: usize,
        stats: Arc<SharedStats>,
        load_balancing_strategy: LoadBalancingStrategy,
        client_ip: String,
        enable_ecs: bool,
        ecs_prefix_v4: u8,
        ecs_prefix_v6: u8,
        spoof_protection: bool,
    ) -> Self {
        // Extract the EDNS0 maximum datagram size from the query, if present
        let max_udp_response_size = match dns_parser::extract_edns0_max_size(&data) {
            Ok(Some(size)) => size as usize,
            _ => dns_parser::DNS_MAX_UDP_PACKET_SIZE,
        };

        Self {
            data,
            upstream_servers,
            server_timeout,
            dns_packet_len_max,
            max_udp_response_size,
            stats: Some(stats),
            load_balancing_strategy,
            client_ip: Some(client_ip),
            enable_ecs,
            ecs_prefix_v4,
            ecs_prefix_v6,
            spoof_protection,
        }
    }

    /// Process the client query by forwarding it to an upstream DNS server
    ///
    /// This is a stub implementation for the library interface.
    /// The actual implementation is in main.rs.
    pub async fn process(&self) -> EtchDnsResult<Vec<u8>> {
        // This is just a stub to make the compiler happy
        // The actual implementation is in main.rs
        Err(DnsError::UpstreamError("Not implemented in library mode".to_string()).into())
    }
}
