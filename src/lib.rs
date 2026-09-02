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
use rand::RngExt;
use stats::SharedStats;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

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
            Ok(Some(size)) => usize::from(size).max(dns_parser::DNS_MAX_UDP_PACKET_SIZE),
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
            Ok(Some(size)) => usize::from(size).max(dns_parser::DNS_MAX_UDP_PACKET_SIZE),
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

    /// Process the client query by forwarding it to an upstream DNS server.
    pub async fn process(&self) -> EtchDnsResult<Vec<u8>> {
        dns_parser::validate_dns_packet(&self.data)?;
        let upstream = load_balancer::select_upstream_server(
            &self.upstream_servers,
            self.load_balancing_strategy,
            self.stats.as_ref(),
        )
        .await
        .ok_or_else(|| DnsError::UpstreamError("No upstream servers configured".to_string()))?;
        let upstream_addr = upstream.parse::<SocketAddr>().map_err(|e| {
            DnsError::UpstreamError(format!("Invalid upstream address {upstream}: {e}"))
        })?;
        let bind_addr = if upstream_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            DnsError::UpstreamError(format!("Failed to bind upstream UDP socket: {e}"))
        })?;

        let mut query = self.data.clone();
        let advertised_size = u16::try_from(self.dns_packet_len_max).unwrap_or(u16::MAX);
        dns_parser::set_edns_max_payload_size(&mut query, advertised_size)?;
        if self.enable_ecs
            && let Some(client_ip) = &self.client_ip
        {
            dns_parser::add_edns_client_subnet(
                &mut query,
                client_ip,
                self.ecs_prefix_v4,
                self.ecs_prefix_v6,
                advertised_size,
            )?;
        }

        let transaction_id: u16 = rand::rng().random();
        dns_parser::set_tid(&mut query, transaction_id)?;
        let start = Instant::now();
        socket.send_to(&query, upstream_addr).await.map_err(|e| {
            DnsError::UpstreamError(format!("Failed to send query to {upstream_addr}: {e}"))
        })?;
        let mut response = vec![0u8; self.dns_packet_len_max];
        let (response_len, response_addr) = tokio::time::timeout(
            Duration::from_secs(self.server_timeout),
            socket.recv_from(&mut response),
        )
        .await
        .map_err(|_| DnsError::UpstreamTimeout)?
        .map_err(|e| {
            DnsError::UpstreamError(format!(
                "Failed to receive response from {upstream_addr}: {e}"
            ))
        })?;

        if response_addr != upstream_addr {
            return Err(DnsError::UpstreamError(format!(
                "Unexpected response source {response_addr}, expected {upstream_addr}"
            ))
            .into());
        }
        response.truncate(response_len);

        let wrong_transaction_id = dns_parser::tid(&response) != transaction_id;
        if wrong_transaction_id && !self.spoof_protection {
            return Err(
                DnsError::UpstreamError("Transaction ID mismatch in response".to_string()).into(),
            );
        }
        if !wrong_transaction_id {
            dns_parser::validate_dns_response(&response)?;
            if !dns_parser::questions_match(&query, &response)? {
                return Err(DnsError::UpstreamError(
                    "Question mismatch in UDP response".to_string(),
                )
                .into());
            }
            if !dns_parser::edns_client_subnet_matches(&query, &response)? {
                return Err(
                    DnsError::UpstreamError("ECS mismatch in UDP response".to_string()).into(),
                );
            }
        }

        if wrong_transaction_id || dns_parser::is_truncated(&response) {
            response = tokio::time::timeout(
                Duration::from_secs(self.server_timeout),
                retry_with_tcp(&query, transaction_id, upstream_addr),
            )
            .await
            .map_err(|_| DnsError::UpstreamTimeout)??;
        }

        if let Some(stats) = &self.stats {
            stats.record_success(upstream_addr, start.elapsed()).await;
        }
        Ok(response)
    }
}

async fn retry_with_tcp(
    query: &[u8],
    expected_transaction_id: u16,
    upstream_addr: SocketAddr,
) -> EtchDnsResult<Vec<u8>> {
    let mut stream = TcpStream::connect(upstream_addr).await.map_err(|e| {
        DnsError::UpstreamError(format!(
            "Failed to connect to {upstream_addr} over TCP: {e}"
        ))
    })?;
    let query_len = u16::try_from(query.len()).map_err(|_| {
        DnsError::InvalidPacket("DNS query is too large for TCP framing".to_string())
    })?;
    stream
        .write_all(&query_len.to_be_bytes())
        .await
        .map_err(|e| DnsError::UpstreamError(format!("Failed to write TCP query length: {e}")))?;
    stream
        .write_all(query)
        .await
        .map_err(|e| DnsError::UpstreamError(format!("Failed to write TCP query: {e}")))?;

    let mut length = [0u8; 2];
    stream
        .read_exact(&mut length)
        .await
        .map_err(|e| DnsError::UpstreamError(format!("Failed to read TCP response length: {e}")))?;
    let response_len = usize::from(u16::from_be_bytes(length));
    if !(dns_parser::DNS_PACKET_LEN_MIN..=dns_parser::DNS_MAX_PACKET_SIZE).contains(&response_len) {
        return Err(DnsError::InvalidPacket(format!(
            "Invalid TCP DNS response length: {response_len}"
        ))
        .into());
    }
    let mut response = vec![0u8; response_len];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|e| DnsError::UpstreamError(format!("Failed to read TCP response: {e}")))?;
    if dns_parser::tid(&response) != expected_transaction_id {
        return Err(
            DnsError::UpstreamError("Transaction ID mismatch in TCP response".to_string()).into(),
        );
    }
    dns_parser::validate_dns_response(&response)?;
    if !dns_parser::questions_match(query, &response)? {
        return Err(
            DnsError::UpstreamError("Question mismatch in TCP response".to_string()).into(),
        );
    }
    if !dns_parser::edns_client_subnet_matches(query, &response)? {
        return Err(DnsError::UpstreamError("ECS mismatch in TCP response".to_string()).into());
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    #[tokio::test]
    async fn public_client_query_reaches_upstream() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut packet = vec![0u8; dns_parser::DNS_MAX_PACKET_SIZE];
            let (length, client) = upstream.recv_from(&mut packet).await.unwrap();
            packet.truncate(length);
            dns_parser::set_qr(&mut packet, true).unwrap();
            upstream.send_to(&packet, client).await.unwrap();
        });
        let client = ClientQuery::new(
            query(),
            vec![upstream_addr.to_string()],
            1,
            1232,
            Arc::new(SharedStats::new()),
            LoadBalancingStrategy::Random,
        );

        let response = client.process().await.unwrap();
        server.await.unwrap();
        assert!(dns_parser::is_response(&response));
    }
}
