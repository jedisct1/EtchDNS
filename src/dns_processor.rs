use log::{debug, warn};

use crate::dns_key::DNSKey;
use crate::dns_parser;
use crate::errors::DnsResult;

/// DNS Response Codes (RCODE)
#[allow(dead_code)]
pub const DNS_RCODE_NOERROR: u8 = 0; // No error
#[allow(dead_code)]
pub const DNS_RCODE_FORMERR: u8 = 1; // Format error
pub const DNS_RCODE_SERVFAIL: u8 = 2; // Server failure
pub const DNS_RCODE_NXDOMAIN: u8 = 3; // Non-existent domain
pub const DNS_RCODE_NOTIMP: u8 = 4; // Not implemented
pub const DNS_RCODE_REFUSED: u8 = 5; // Query refused
pub const DNS_RCODE_BADVERS: u8 = 16; // Bad EDNS version

/// Validates a DNS packet and creates a DNSKey from it
pub fn validate_and_create_key(packet: &[u8], client_addr: &str) -> DnsResult<DNSKey> {
    // Validate that this is a valid DNS packet
    if let Err(e) = dns_parser::validate_dns_packet(packet) {
        // If validation fails, log the error and return without responding
        debug!("Invalid DNS packet from {client_addr}: {e}");
        debug!("Dropping invalid DNS packet without response");
        return Err(e);
    }

    // Create a DNSKey from the packet
    match DNSKey::from_packet(packet) {
        Ok(key) => Ok(key),
        Err(e) => {
            debug!("Failed to create DNSKey from packet from {client_addr}: {e}");
            debug!("Error details: {e:?}");
            Err(e)
        }
    }
}

/// Logs information about a received DNS packet
pub fn log_received_packet(packet_size: usize, client_addr: &str, protocol: &str) {
    log::debug!("Received {packet_size} bytes from {protocol} client {client_addr}");
}

/// Creates a DNS response with the specified response code
pub fn create_dns_response(query_data: &[u8], rcode: u8, log_msg: Option<&str>) -> Vec<u8> {
    // Log the message if provided
    if let Some(msg) = log_msg {
        log::debug!("{msg}");
    }

    // Create a response based on the query
    let mut response = query_data.to_vec();

    // Set QR bit to 1 (response)
    if let Err(e) = dns_parser::set_qr(&mut response, true) {
        log::error!("Failed to set QR bit: {e}");
    }

    // Set the specified RCODE
    if let Err(e) = dns_parser::set_rcode(&mut response, rcode) {
        log::error!("Failed to set RCODE: {e}");
    }

    response
}

/// Creates a response with a specific RCODE for a query
#[allow(dead_code)]
pub fn create_response_with_rcode(query_data: &[u8], rcode: u8) -> Vec<u8> {
    create_dns_response(query_data, rcode, None)
}

/// Creates a BADVERS response for unsupported EDNS version
pub fn create_badvers_response(query_data: &[u8]) -> Vec<u8> {
    // For BADVERS (RCODE 16), we need to handle extended RCODE
    // The lower 4 bits go in the header (0), and the upper 8 bits go in OPT
    let mut response = create_dns_response(query_data, DNS_RCODE_BADVERS, None);

    // We need to manually create an OPT record with extended RCODE
    // First, let's build the OPT record with extended RCODE = 1 (upper 8 bits of 16)
    let opt_record: Vec<u8> = vec![
        0, // Root domain name
        0, 41, // Type = OPT
        0x04, 0xd0, // Class = 1232 (UDP payload size)
        1,    // Extended RCODE = 1 (upper 8 bits of RCODE 16)
        0,    // EDNS Version = 0
        0, 0, // Flags
        0, 0, // RDLEN = 0
    ];

    // Update ARCOUNT
    let arcount_offset = 10;
    if response.len() > arcount_offset + 2 {
        let arcount = dns_parser::arcount(&response);
        dns_parser::set_arcount(&mut response, arcount + 1).unwrap_or_else(|e| {
            log::error!("Failed to update ARCOUNT: {e}");
        });

        // Append OPT record
        response.extend_from_slice(&opt_record);
    }

    response
}

/// Sets the appropriate DNS response flags based on authoritative_dns setting
pub fn set_response_flags(response_data: &mut [u8], authoritative_dns: bool) {
    // Set AA (Authoritative Answer) flag based on authoritative_dns setting
    if let Err(e) = dns_parser::set_aa(response_data, authoritative_dns) {
        log::error!("Failed to set AA bit: {e}");
    }

    // Set RA (Recursion Available) flag based on authoritative_dns setting
    // If authoritative_dns is false, we're a recursive resolver, so RA should be true
    if let Err(e) = dns_parser::set_ra(response_data, !authoritative_dns) {
        log::error!("Failed to set RA bit: {e}");
    }
}

/// Trait for processing DNS queries
pub trait DnsQueryProcessor {
    /// Process a DNS query and get a response
    ///
    /// This function handles the common logic for processing a DNS query,
    /// including validating the packet, creating a DNSKey, and submitting
    /// the query to the query manager.
    ///
    /// # Arguments
    ///
    /// * `query_data` - The raw DNS query data
    /// * `client_addr` - A string representation of the client address for logging
    /// * `protocol` - The protocol used (e.g., "UDP", "TCP", "DoH")
    /// * `query_manager` - The query manager for aggregating identical DNS queries
    /// * `upstream_servers` - The upstream DNS servers to forward queries to
    /// * `server_timeout` - The timeout for upstream servers in seconds
    /// * `dns_packet_len_max` - The maximum DNS packet size
    /// * `stats` - The global statistics tracker
    /// * `load_balancing_strategy` - The load balancing strategy to use
    ///
    /// # Returns
    ///
    /// * `Some((Vec<u8>, u16))` - The response data and client query ID if successful
    /// * `None` - If the query could not be processed
    #[allow(async_fn_in_trait)]
    async fn process_dns_query(
        &self,
        query_data: &[u8],
        client_addr: &str,
        protocol: &str,
        query_manager: &std::sync::Arc<crate::query_manager::QueryManager>,
        upstream_servers: &[String],
        server_timeout: u64,
        dns_packet_len_max: usize,
        stats: Option<std::sync::Arc<crate::stats::SharedStats>>,
        load_balancing_strategy: crate::load_balancer::LoadBalancingStrategy,
    ) -> Option<(Vec<u8>, u16)> {
        // Log the received packet
        log_received_packet(query_data.len(), client_addr, protocol);

        // Validate the packet and create a DNSKey
        let dns_key = match validate_and_create_key(query_data, client_addr) {
            Ok(key) => key,
            Err(e) => {
                // Check if this is an unsupported EDNS version error
                if let crate::errors::DnsError::UnsupportedEdnsVersion { version } = e {
                    debug!(
                        "Unsupported EDNS version {version} from {client_addr}, returning BADVERS"
                    );
                    let response = create_badvers_response(query_data);
                    let client_query_id = crate::dns_parser::tid(query_data);
                    return Some((response, client_query_id));
                }
                return None; // Error already logged in validate_and_create_key
            }
        };

        // Get the client query ID once to avoid multiple calls
        let client_query_id = crate::dns_parser::tid(query_data);

        // Extract client IP and prepare the resolver
        let client_ip = extract_client_ip(client_addr);
        let resolver = prepare_resolver(
            query_manager,
            upstream_servers,
            server_timeout,
            dns_packet_len_max,
            stats,
            load_balancing_strategy,
            &client_ip,
        );

        // Submit the query and handle the response
        submit_query_and_get_response(
            query_manager,
            dns_key,
            query_data,
            resolver,
            client_addr,
            client_query_id,
        )
        .await
        .map(|response_data| (response_data, client_query_id))
    }
}

/// Extracts the client IP from a client address string
fn extract_client_ip(client_addr: &str) -> String {
    if let Ok(sa) = client_addr.parse::<std::net::SocketAddr>() {
        return sa.ip().to_string();
    }
    if let Ok(ip) = client_addr.parse::<std::net::IpAddr>() {
        return ip.to_string();
    }
    warn!("Unable to parse client address: {client_addr}, using 'unknown'");
    "unknown".to_string()
}

/// Prepares a resolver function for a DNS query
fn prepare_resolver(
    query_manager: &std::sync::Arc<crate::query_manager::QueryManager>,
    upstream_servers: &[String],
    server_timeout: u64,
    dns_packet_len_max: usize,
    stats: Option<std::sync::Arc<crate::stats::SharedStats>>,
    load_balancing_strategy: crate::load_balancer::LoadBalancingStrategy,
    client_ip: &str,
) -> impl Fn(Vec<u8>) -> futures::future::BoxFuture<'static, crate::errors::DnsResult<Vec<u8>>>
+ Send
+ Sync
+ 'static {
    // Get ECS configuration from query_manager
    let enable_ecs = query_manager.get_enable_ecs();
    let ecs_prefix_v4 = query_manager.get_ecs_prefix_v4();
    let ecs_prefix_v6 = query_manager.get_ecs_prefix_v6();

    // Create a resolver function for this query
    crate::resolver::create_resolver_with_client_ip(
        upstream_servers.to_vec(),
        server_timeout,
        dns_packet_len_max,
        stats,
        load_balancing_strategy,
        client_ip.to_string(),
        enable_ecs,
        ecs_prefix_v4,
        ecs_prefix_v6,
    )
}

/// Submits a query to the query manager and waits for a response
async fn submit_query_and_get_response(
    query_manager: &std::sync::Arc<crate::query_manager::QueryManager>,
    dns_key: DNSKey,
    query_data: &[u8],
    resolver: impl Fn(Vec<u8>) -> futures::future::BoxFuture<'static, crate::errors::DnsResult<Vec<u8>>>
    + Send
    + Sync
    + 'static,
    client_addr: &str,
    client_query_id: u16,
) -> Option<Vec<u8>> {
    // Submit the query to the query manager with client address
    match query_manager
        .submit_query_with_client(dns_key, query_data.to_vec(), resolver, client_addr)
        .await
    {
        Ok(mut receiver) => {
            // Wait for the response
            match receiver.recv().await {
                Ok(response) => {
                    // Process the response
                    process_dns_response(response, client_query_id, client_addr)
                }
                Err(e) => {
                    log::debug!("Failed to receive response from query manager: {e}");
                    log::debug!("Error details: {e:?}");
                    None
                }
            }
        }
        Err(e) => {
            log::debug!("Failed to submit query to query manager: {e}");
            log::debug!("Error details: {e:?}");
            None
        }
    }
}

/// Processes a DNS response and updates the transaction ID
fn process_dns_response(
    response: crate::query_manager::DnsResponse,
    client_query_id: u16,
    client_addr: &str,
) -> Option<Vec<u8>> {
    // Check if the response contains an error
    if let Some(error_msg) = response.error {
        // Log the error
        log::debug!("Error in DNS response: {error_msg}");
        log::debug!("Not sending error response to client {client_addr}");
        return None;
    }

    // Get the response data (no need to clone as we own it)
    let mut response_data = response.data;

    // Replace the query ID in the response with the client's query ID
    if let Err(e) = crate::dns_parser::set_tid(&mut response_data, client_query_id) {
        log::debug!("Failed to set transaction ID in response: {e}");
        None
    } else {
        log::debug!("Replaced response transaction ID with client query ID: {client_query_id}");
        Some(response_data)
    }
}

/// Trait for processing DNS queries
impl DnsQueryProcessor for () {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_parser;

    fn create_test_query_with_edns_version(version: u8) -> Vec<u8> {
        // Create a basic DNS query
        let query = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x01, // ARCOUNT = 1 (for OPT record)
            // Question section
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0x03, b'c', b'o', b'm', // "com"
            0x00, // Root label
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // Additional section - OPT record
            0x00, // Root domain name
            0x00, 0x29, // Type = OPT (41)
            0x04, 0xd0,    // Class = 1232 (UDP payload size)
            0x00,    // Extended RCODE
            version, // EDNS Version
            0x00, 0x00, // Flags
            0x00, 0x00, // RDLEN = 0
        ];
        query
    }

    #[test]
    fn test_create_badvers_response() {
        // Create a query with EDNS version 1
        let query = create_test_query_with_edns_version(1);

        // Create BADVERS response
        let response = create_badvers_response(&query);

        // Check that it's a response
        assert!(dns_parser::is_response(&response));

        // For extended RCODE 16 (BADVERS), the header RCODE should be 0
        // and the extended part (1) should be in the OPT record
        assert_eq!(dns_parser::rcode(&response), 0);

        // Check that response includes an OPT record
        assert!(dns_parser::arcount(&response) > 0);

        // Check that the OPT record has EDNS version 0
        let edns_version = dns_parser::extract_edns_version(&response).unwrap();
        assert_eq!(edns_version, Some(0));

        // Verify the OPT record structure
        // Find the OPT record - it should be at the end
        let response_len = response.len();
        assert!(response_len >= 11); // Should have at least the OPT record

        // The OPT record starts 11 bytes from the end
        let opt_start = response_len - 11;

        // Verify OPT record structure
        assert_eq!(response[opt_start], 0); // Root domain
        assert_eq!(response[opt_start + 1], 0); // Type high byte
        assert_eq!(response[opt_start + 2], 41); // Type low byte (OPT)
        // Skip class (UDP payload size)
        assert_eq!(response[opt_start + 5], 1); // Extended RCODE = 1
        assert_eq!(response[opt_start + 6], 0); // EDNS version = 0
    }

    #[test]
    fn test_unsupported_edns_version_validation() {
        // Test that EDNS version 0 passes validation
        let query_v0 = create_test_query_with_edns_version(0);
        let result = validate_and_create_key(&query_v0, "127.0.0.1:12345");
        assert!(result.is_ok());

        // Test that EDNS version 1 fails validation
        let query_v1 = create_test_query_with_edns_version(1);
        let result = validate_and_create_key(&query_v1, "127.0.0.1:12345");
        assert!(result.is_err());
        match result {
            Err(crate::errors::DnsError::UnsupportedEdnsVersion { version }) => {
                assert_eq!(version, 1);
            }
            _ => panic!("Expected UnsupportedEdnsVersion error"),
        }

        // Test that EDNS version 2 fails validation
        let query_v2 = create_test_query_with_edns_version(2);
        let result = validate_and_create_key(&query_v2, "127.0.0.1:12345");
        assert!(result.is_err());
        match result {
            Err(crate::errors::DnsError::UnsupportedEdnsVersion { version }) => {
                assert_eq!(version, 2);
            }
            _ => panic!("Expected UnsupportedEdnsVersion error"),
        }
    }
}
