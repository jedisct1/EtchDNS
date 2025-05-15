use log::{debug, warn};
use std::sync::Arc;

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

/// Validates a DNS packet and creates a DNSKey from it
///
/// This function combines the common validation and key creation logic
/// used across different client implementations.
///
/// # Arguments
///
/// * `packet` - The raw DNS packet data
/// * `client_addr` - A string representation of the client address for logging
///
/// # Returns
///
/// * `Ok(DNSKey)` - If the packet is valid and a key could be created
/// * `Err(DnsError)` - If the packet is invalid or a key could not be created
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
///
/// # Arguments
///
/// * `packet_size` - The size of the received packet in bytes
/// * `client_addr` - A string representation of the client address
/// * `protocol` - The protocol used (e.g., "UDP", "TCP", "DoH")
pub fn log_received_packet(packet_size: usize, client_addr: &str, protocol: &str) {
    log::debug!("Received {packet_size} bytes from {protocol} client {client_addr}");
}

/// Creates a DNS response with the specified response code
///
/// This is a generic function that can create various types of DNS responses
/// by setting the appropriate response code (RCODE).
///
/// # Arguments
///
/// * `query_data` - The raw query data to base the response on
/// * `rcode` - The DNS response code to set in the response
/// * `log_msg` - Optional log message to display when creating the response
///
/// # Returns
///
/// * `Vec<u8>` - The DNS response with the specified RCODE
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

/// Checks if a query is of type ANY and creates a NOTIMP response if it is
///
/// # Arguments
///
/// * `key` - The DNSKey representing the query
/// * `query_data` - The raw query data
///
/// # Returns
///
/// * `Some(Vec<u8>)` - If the query is of type ANY, returns a NOTIMP response
/// * `None` - If the query is not of type ANY
#[allow(dead_code)]
pub fn handle_any_query(key: &DNSKey, query_data: &[u8]) -> Option<Vec<u8>> {
    if key.qtype == dns_parser::DNS_TYPE_ANY {
        let log_msg = format!(
            "Received query of type ANY for {}, returning NOTIMP",
            key.name
        );
        return Some(create_dns_response(
            query_data,
            DNS_RCODE_NOTIMP,
            Some(&log_msg),
        ));
    }

    None
}

/// Creates a response with a specific RCODE for a query
///
/// # Arguments
///
/// * `query_data` - The raw query data
/// * `rcode` - The response code to set
///
/// # Returns
///
/// * `Vec<u8>` - The response with the specified RCODE
pub fn create_response_with_rcode(query_data: &[u8], rcode: u8) -> Vec<u8> {
    create_dns_response(query_data, rcode, None)
}

/// Creates a REFUSED response for a query
///
/// # Arguments
///
/// * `query_data` - The raw query data
///
/// # Returns
///
/// * `Vec<u8>` - The REFUSED response
#[allow(dead_code)]
pub fn create_refused_response(query_data: &[u8]) -> Vec<u8> {
    create_response_with_rcode(query_data, DNS_RCODE_REFUSED)
}

/// Sets the appropriate DNS response flags based on authoritative_dns setting
///
/// This function sets the AA (Authoritative Answer) and RA (Recursion Available)
/// flags in a DNS response based on whether the server is authoritative or not.
///
/// # Arguments
///
/// * `response_data` - The DNS response data to modify
/// * `authoritative_dns` - Whether the server is authoritative for the response
///
/// # Returns
///
/// * `()` - The function modifies the response_data in place
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

/// Process a client query through the query manager
///
/// This function handles the common logic for processing a client query,
/// including validating the packet, creating a DNSKey, and submitting
/// the query to the query manager.
///
/// # Arguments
///
/// * `query_data` - The raw DNS query data
/// * `client_addr` - A string representation of the client address for logging
/// * `query_manager` - The query manager for aggregating identical DNS queries
/// * `upstream_servers` - The upstream DNS servers to forward queries to
/// * `server_timeout` - The timeout for upstream servers in seconds
/// * `dns_packet_len_max` - The maximum DNS packet size
/// * `stats` - The global statistics tracker
/// * `load_balancing_strategy` - The load balancing strategy to use
///
/// # Returns
///
/// * `Ok(receiver)` - A receiver for the query response
/// * `Err(e)` - If the query could not be processed
#[allow(dead_code)]
pub async fn process_client_query<T>(
    query_data: &[u8],
    client_addr: &str,
    query_manager: &T,
    upstream_servers: Vec<String>,
    server_timeout: u64,
    dns_packet_len_max: usize,
    stats: Arc<crate::stats::SharedStats>,
    load_balancing_strategy: crate::load_balancer::LoadBalancingStrategy,
) -> crate::errors::EtchDnsResult<tokio::sync::broadcast::Receiver<crate::query_manager::DnsResponse>>
where
    T: AsRef<crate::query_manager::QueryManager>,
{
    // Validate the packet and create a DNSKey
    let dns_key = match validate_and_create_key(query_data, client_addr) {
        Ok(key) => key,
        Err(e) => return Err(e.into()),
    };

    // Create a resolver function for this query
    let resolver = crate::resolver::create_resolver(
        upstream_servers,
        server_timeout,
        dns_packet_len_max,
        Some(stats),
        load_balancing_strategy,
    );

    // Submit the query to the query manager
    query_manager
        .as_ref()
        .submit_query(dns_key, query_data.to_vec(), resolver)
        .await
}

/// Trait for processing DNS queries
///
/// This trait provides a common implementation for processing DNS queries
/// across different client types (UDP, TCP, DoH).
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
            Err(_) => return None, // Error already logged in validate_and_create_key
        };

        // Get the client query ID once to avoid multiple calls
        let client_query_id = crate::dns_parser::tid(query_data);

        // Extract client IP (without port) for EDNS-client-subnet
        let client_ip = if let Some(ip) = client_addr.split(':').next() {
            ip.to_string()
        } else {
            warn!(
                "Unable to parse client address: {}, using 'unknown'",
                client_addr
            );
            "unknown".to_string()
        };

        // Get ECS configuration from query_manager
        let enable_ecs = query_manager.get_enable_ecs();
        let ecs_prefix_v4 = query_manager.get_ecs_prefix_v4();
        let ecs_prefix_v6 = query_manager.get_ecs_prefix_v6();

        // Create a resolver function for this query
        let resolver = crate::resolver::create_resolver_with_client_ip(
            upstream_servers.to_vec(),
            server_timeout,
            dns_packet_len_max,
            stats,
            load_balancing_strategy,
            client_ip,
            enable_ecs,
            ecs_prefix_v4,
            ecs_prefix_v6,
        );

        // Submit the query to the query manager with client address
        match query_manager
            .submit_query_with_client(dns_key, query_data.to_vec(), resolver, client_addr)
            .await
        {
            Ok(mut receiver) => {
                // Wait for the response
                match receiver.recv().await {
                    Ok(response) => {
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
                        if let Err(e) =
                            crate::dns_parser::set_tid(&mut response_data, client_query_id)
                        {
                            log::debug!("Failed to set transaction ID in response: {e}");
                            return None;
                        } else {
                            log::debug!(
                                "Replaced response transaction ID with client query ID: {client_query_id}"
                            );
                        }

                        // Return the response data and client query ID
                        Some((response_data, client_query_id))
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
}
