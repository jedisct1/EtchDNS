use async_trait::async_trait;
use clap::Parser;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use slabigator::Slab;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

mod allowed_zones;
mod cache;
mod control;
mod dns_key;
mod dns_key_test;
mod dns_parser;
mod dns_processor;
mod doh;
mod errors;
mod hooks;
mod load_balancer;
mod metrics;
mod nx_zones;
mod probe;
mod query_logger;
mod query_manager;
mod rate_limiter;
mod resolver;
mod stats;

// Use our error types
use dns_processor::DnsQueryProcessor;
use errors::{DnsError, EtchDnsError, EtchDnsResult};
use probe::probe_server;
use query_manager::QueryManager;
use stats::SharedStats;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
#[macro_use]
extern crate bpf;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about = "An efficient caching DNS proxy")]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,
}

/// Configuration structure for the application
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    log_level: String,

    /// Addresses to listen on (array of "ip:port" strings)
    #[serde(default = "default_listen_addresses")]
    listen_addresses: Vec<String>,

    /// Addresses to listen on for DNS-over-HTTPS (DoH) (array of "ip:port" strings)
    #[serde(default = "default_doh_listen_addresses")]
    doh_listen_addresses: Vec<String>,

    /// Maximum length of DNS packet in bytes
    #[serde(default = "default_packet_size")]
    dns_packet_len_max: usize,

    /// Maximum number of UDP clients to keep in the slab
    #[serde(default = "default_max_udp_clients")]
    max_udp_clients: usize,

    /// Maximum number of TCP clients to keep in the slab
    #[serde(default = "default_max_tcp_clients")]
    max_tcp_clients: usize,

    /// Maximum number of simultaneous in-flight queries
    #[serde(default = "default_max_inflight_queries")]
    max_inflight_queries: usize,

    /// Maximum time (in seconds) to wait for a response from an upstream server
    #[serde(default = "default_server_timeout")]
    server_timeout: u64,

    /// Upstream DNS servers to forward queries to (array of "ip:port" strings)
    #[serde(default = "default_upstream_servers")]
    upstream_servers: Vec<String>,

    /// Load balancing strategy for upstream DNS servers
    /// Options: "random", "fastest", "p2" (power-of-two-choices)
    #[serde(default = "default_load_balancing_strategy")]
    load_balancing_strategy: String,

    /// Optional address for the HTTP metrics server (ip:port)
    #[serde(default)]
    metrics_address: Option<String>,

    /// Optional URL path for the metrics endpoint (e.g., "/metrics")
    #[serde(default = "default_metrics_path")]
    metrics_path: String,

    /// Time window in seconds for UDP rate limiting
    /// Set to 0 to disable rate limiting for UDP
    #[serde(default = "default_udp_rate_limit_window")]
    udp_rate_limit_window: u64,

    /// Maximum number of queries allowed per client IP in the UDP window
    #[serde(default = "default_udp_rate_limit_count")]
    udp_rate_limit_count: u32,

    /// Maximum number of client IPs to track for UDP rate limiting
    #[serde(default = "default_udp_rate_limit_max_clients")]
    udp_rate_limit_max_clients: usize,

    /// Time window in seconds for TCP rate limiting
    /// Set to 0 to disable rate limiting for TCP
    #[serde(default = "default_tcp_rate_limit_window")]
    tcp_rate_limit_window: u64,

    /// Maximum number of queries allowed per client IP in the TCP window
    #[serde(default = "default_tcp_rate_limit_count")]
    tcp_rate_limit_count: u32,

    /// Maximum number of client IPs to track for TCP rate limiting
    #[serde(default = "default_tcp_rate_limit_max_clients")]
    tcp_rate_limit_max_clients: usize,

    /// Time window in seconds for DoH rate limiting
    /// Set to 0 to disable rate limiting for DoH
    #[serde(default = "default_doh_rate_limit_window")]
    doh_rate_limit_window: u64,

    /// Maximum number of queries allowed per client IP in the DoH window
    #[serde(default = "default_doh_rate_limit_count")]
    doh_rate_limit_count: u32,

    /// Maximum number of client IPs to track for DoH rate limiting
    #[serde(default = "default_doh_rate_limit_max_clients")]
    doh_rate_limit_max_clients: usize,

    /// Maximum number of concurrent connections to the HTTP metrics server
    #[serde(default = "default_max_metrics_connections")]
    max_metrics_connections: usize,

    /// Maximum number of concurrent connections to the DoH server
    #[serde(default = "default_max_doh_connections")]
    max_doh_connections: usize,

    /// Addresses to listen on for the HTTP control server (array of "ip:port" strings)
    #[serde(default = "default_control_listen_addresses")]
    control_listen_addresses: Vec<String>,

    /// Maximum number of concurrent connections to the HTTP control server
    #[serde(default = "default_max_control_connections")]
    max_control_connections: usize,

    /// Base path for the control API endpoints
    #[serde(default = "default_control_path")]
    control_path: String,

    /// Interval between DNS server probes in seconds (0 to disable)
    #[serde(default = "default_probe_interval")]
    probe_interval: u64,

    /// Size of the DNS cache in number of entries
    #[serde(default = "default_cache_size")]
    cache_size: usize,

    /// Whether this server is authoritative for DNS responses
    /// If false (default), TTLs in cached responses will be adjusted based on remaining time
    #[serde(default = "default_authoritative_dns")]
    authoritative_dns: bool,

    /// Path to a file containing allowed zones
    /// If set, only queries for domains in this file will be processed
    #[serde(default)]
    allowed_zones_file: Option<String>,

    /// Path to a file containing nonexistent zones
    /// If set, queries for domains in this file will return NXDOMAIN directly
    #[serde(default)]
    nx_zones_file: Option<String>,

    /// Grace period in seconds to serve stale (expired) cache entries when upstream servers fail
    /// Set to 0 to disable serving stale entries (default: 0)
    #[serde(default = "default_serve_stale_grace_time")]
    serve_stale_grace_time: u64,

    /// TTL in seconds to use when serving stale cache entries
    /// This is the TTL that will be set in the response (default: 30)
    #[serde(default = "default_serve_stale_ttl")]
    serve_stale_ttl: u32,

    /// TTL in seconds to use for negative DNS responses when no TTL is available
    /// This is used when extract_min_ttl() doesn't return a TTL (default: 1)
    #[serde(default = "default_negative_cache_ttl")]
    negative_cache_ttl: u32,

    /// Minimum TTL in seconds for cached DNS responses
    /// This is the minimum time a valid response will be stored in the cache (default: 1)
    #[serde(default = "default_min_cache_ttl")]
    min_cache_ttl: u32,

    /// Path to a WebAssembly file containing hook implementations
    /// If set, the hooks will be loaded from this file
    #[serde(default)]
    #[cfg(feature = "hooks")]
    hooks_wasm_file: Option<String>,

    /// This field is a placeholder when hooks feature is disabled
    #[serde(default, skip)]
    #[cfg(not(feature = "hooks"))]
    hooks_wasm_file: Option<String>,

    /// Enable WASI support for WebAssembly hooks
    /// If true, the WebAssembly module will have access to WASI system calls
    #[serde(default)]
    #[cfg(feature = "hooks")]
    hooks_wasm_wasi: bool,

    /// This field is a placeholder when hooks feature is disabled
    #[serde(default, skip)]
    #[cfg(not(feature = "hooks"))]
    hooks_wasm_wasi: bool,

    /// Path to a file to log DNS queries to
    /// If not set, query logging is disabled
    #[serde(default)]
    query_log_file: Option<String>,

    /// Whether to include timestamp in query log
    #[serde(default = "default_query_log_include_timestamp")]
    query_log_include_timestamp: bool,

    /// Whether to include client address in query log
    #[serde(default = "default_query_log_include_client_addr")]
    query_log_include_client_addr: bool,

    /// Whether to include query type in query log
    #[serde(default = "default_query_log_include_query_type")]
    query_log_include_query_type: bool,

    /// Whether to include query class in query log
    #[serde(default = "default_query_log_include_query_class")]
    query_log_include_query_class: bool,

    /// Username to drop privileges to after binding to sockets
    /// If not set, privileges will not be dropped
    #[serde(default)]
    user: Option<String>,

    /// Group to drop privileges to after binding to sockets
    /// If not set, the primary group of the user will be used
    #[serde(default)]
    group: Option<String>,

    /// Directory to chroot to after binding to sockets
    /// If not set, chroot will not be performed
    #[serde(default)]
    chroot: Option<String>,

    /// Enable EDNS-client-subnet support
    /// If true, client IP information will be included in upstream queries
    #[serde(default = "default_enable_ecs")]
    enable_ecs: bool,

    /// IPv4 prefix length to use for EDNS-client-subnet
    /// This controls how much of the client's IPv4 address is sent to upstream servers
    /// Recommended values: 24 (send first 24 bits, hiding the last 8 bits)
    #[serde(default = "default_ecs_prefix_v4")]
    ecs_prefix_v4: u8,

    /// IPv6 prefix length to use for EDNS-client-subnet
    /// This controls how much of the client's IPv6 address is sent to upstream servers
    /// Recommended values: 56 (send first 56 bits, hiding the last 72 bits)
    #[serde(default = "default_ecs_prefix_v6")]
    ecs_prefix_v6: u8,
}

// Default values for configuration
fn default_listen_addresses() -> Vec<String> {
    vec!["0.0.0.0:10000".to_string()]
}

fn default_doh_listen_addresses() -> Vec<String> {
    Vec::new() // Empty by default, DoH is disabled
}

fn default_packet_size() -> usize {
    4096
}

fn default_max_udp_clients() -> usize {
    1000
}

fn default_max_tcp_clients() -> usize {
    1000
}

fn default_max_inflight_queries() -> usize {
    500
}

fn default_server_timeout() -> u64 {
    5 // 5 seconds default timeout
}

fn default_upstream_servers() -> Vec<String> {
    vec!["8.8.8.8:53".to_string(), "8.8.4.4:53".to_string()]
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

fn default_max_metrics_connections() -> usize {
    5
}

fn default_max_doh_connections() -> usize {
    10 // Default to 10 concurrent DoH connections
}

fn default_control_listen_addresses() -> Vec<String> {
    Vec::new() // Empty by default, control server is disabled
}

fn default_max_control_connections() -> usize {
    5 // Default to 5 concurrent control connections
}

fn default_control_path() -> String {
    "/control".to_string() // Default control API base path
}

fn default_load_balancing_strategy() -> String {
    "fastest".to_string()
}

fn default_probe_interval() -> u64 {
    60 // 60 seconds default probe interval
}

fn default_cache_size() -> usize {
    10000 // 10,000 entries default cache size
}

fn default_authoritative_dns() -> bool {
    false // Default is false, meaning TTLs will be adjusted
}

fn default_serve_stale_grace_time() -> u64 {
    0 // 0 seconds means disabled by default
}

fn default_serve_stale_ttl() -> u32 {
    30 // 30 seconds default TTL for stale entries
}

fn default_udp_rate_limit_window() -> u64 {
    1 // 1 second window for UDP rate limiting
}

fn default_udp_rate_limit_count() -> u32 {
    100 // Allow 100 queries per second per client IP for UDP
}

fn default_tcp_rate_limit_window() -> u64 {
    5 // 5 second window for TCP rate limiting
}

fn default_tcp_rate_limit_count() -> u32 {
    20 // Allow 20 queries per 5 seconds per client IP for TCP
}

fn default_udp_rate_limit_max_clients() -> usize {
    10000 // Track up to 10,000 client IPs for UDP rate limiting
}

fn default_tcp_rate_limit_max_clients() -> usize {
    5000 // Track up to 5,000 client IPs for TCP rate limiting
}

fn default_doh_rate_limit_window() -> u64 {
    10 // 10 second window for DoH rate limiting
}

fn default_doh_rate_limit_count() -> u32 {
    30 // Allow 30 queries per 10 seconds per client IP for DoH
}

fn default_doh_rate_limit_max_clients() -> usize {
    5000 // Track up to 5,000 client IPs for DoH rate limiting
}

fn default_log_level() -> String {
    "info".to_string() // Default log level is INFO
}

fn default_negative_cache_ttl() -> u32 {
    1 // Default TTL for negative responses is 1 second
}

fn default_min_cache_ttl() -> u32 {
    1 // Default minimum TTL for cached responses is 1 second
}

fn default_query_log_include_timestamp() -> bool {
    true // Include timestamp in query log by default
}

fn default_query_log_include_client_addr() -> bool {
    true // Include client address in query log by default
}

fn default_query_log_include_query_type() -> bool {
    true // Include query type in query log by default
}

fn default_query_log_include_query_class() -> bool {
    false // Don't include query class in query log by default
}

fn default_enable_ecs() -> bool {
    false // EDNS-client-subnet is disabled by default
}

fn default_ecs_prefix_v4() -> u8 {
    24 // Send first 24 bits of IPv4 address (hide last 8 bits)
}

fn default_ecs_prefix_v6() -> u8 {
    56 // Send first 56 bits of IPv6 address (hide last 72 bits)
}

impl Config {
    /// Load configuration from a TOML file
    fn from_file(path: &PathBuf) -> EtchDnsResult<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            EtchDnsError::ConfigReadError(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;

        let config: Config = toml::from_str(&content).map_err(|e| {
            EtchDnsError::ConfigParseError(format!(
                "Failed to parse config file {}: {}",
                path.display(),
                e
            ))
        })?;

        // Validate the configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> EtchDnsResult<()> {
        // Validate log level
        match self.log_level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {}
            _ => {
                return Err(EtchDnsError::Other(format!(
                    "Invalid log level: {}. Must be one of: trace, debug, info, warn, error",
                    self.log_level
                )));
            }
        }

        // Check DNS packet size limits
        if self.dns_packet_len_max < 512 || self.dns_packet_len_max >= 65536 {
            return Err(EtchDnsError::Other(format!(
                "Invalid DNS packet size: {}. Must be between 512 and 65536 bytes",
                self.dns_packet_len_max
            )));
        }

        // Check max_inflight_queries limits
        if self.max_inflight_queries < 1 {
            return Err(EtchDnsError::Other(format!(
                "Invalid max_inflight_queries: {}. Must be at least 1",
                self.max_inflight_queries
            )));
        }

        // Check server_timeout limits
        if self.server_timeout < 1 {
            return Err(EtchDnsError::Other(format!(
                "Invalid server_timeout: {}. Must be at least 1 second",
                self.server_timeout
            )));
        }

        // Validate each listen address
        for addr_str in &self.listen_addresses {
            addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!("Invalid socket address {addr_str}: {e}"))
            })?;
        }

        // Validate each DoH listen address
        for addr_str in &self.doh_listen_addresses {
            addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!("Invalid DoH socket address {addr_str}: {e}"))
            })?;
        }

        // Validate each control server listen address
        for addr_str in &self.control_listen_addresses {
            addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!(
                    "Invalid control server socket address {addr_str}: {e}"
                ))
            })?;
        }

        // Validate the load balancing strategy
        self.load_balancing_strategy
            .parse::<load_balancer::LoadBalancingStrategy>()
            .map_err(|e| EtchDnsError::Other(format!("Invalid load balancing strategy: {e}")))?;

        // Validate rate limiting parameters
        if self.udp_rate_limit_window > 0 && self.udp_rate_limit_count == 0 {
            return Err(EtchDnsError::Other(
                "Invalid udp_rate_limit_count: must be greater than 0 when rate limiting is enabled".to_string(),
            ));
        }

        if self.tcp_rate_limit_window > 0 && self.tcp_rate_limit_count == 0 {
            return Err(EtchDnsError::Other(
                "Invalid tcp_rate_limit_count: must be greater than 0 when rate limiting is enabled".to_string(),
            ));
        }

        if self.udp_rate_limit_window > 0 && self.udp_rate_limit_max_clients == 0 {
            return Err(EtchDnsError::Other(
                "Invalid udp_rate_limit_max_clients: must be greater than 0 when rate limiting is enabled".to_string(),
            ));
        }

        if self.tcp_rate_limit_window > 0 && self.tcp_rate_limit_max_clients == 0 {
            return Err(EtchDnsError::Other(
                "Invalid tcp_rate_limit_max_clients: must be greater than 0 when rate limiting is enabled".to_string(),
            ));
        }

        // Validate EDNS-client-subnet parameters
        if self.enable_ecs {
            if self.ecs_prefix_v4 > 32 {
                return Err(EtchDnsError::Other(format!(
                    "Invalid ecs_prefix_v4: {}. Must be between 0 and 32",
                    self.ecs_prefix_v4
                )));
            }
            if self.ecs_prefix_v6 > 128 {
                return Err(EtchDnsError::Other(format!(
                    "Invalid ecs_prefix_v6: {}. Must be between 0 and 128",
                    self.ecs_prefix_v6
                )));
            }
        }

        // Validate DoH rate limiting parameters
        if self.doh_rate_limit_window > 0 && self.doh_rate_limit_count == 0 {
            return Err(EtchDnsError::Other(
                "Invalid doh_rate_limit_count: must be greater than 0 when rate limiting is enabled".to_string(),
            ));
        }

        if self.doh_rate_limit_window > 0 && self.doh_rate_limit_max_clients == 0 {
            return Err(EtchDnsError::Other(
                "Invalid doh_rate_limit_max_clients: must be greater than 0 when rate limiting is enabled".to_string(),
            ));
        }

        // Validate privilege dropping parameters
        if let Some(chroot_dir) = &self.chroot {
            // Check if the chroot directory exists
            if !std::path::Path::new(chroot_dir).exists() {
                return Err(EtchDnsError::Other(format!(
                    "Chroot directory '{chroot_dir}' does not exist"
                )));
            }

            // If user is not set but chroot is, that's an error
            if self.user.is_none() {
                return Err(EtchDnsError::Other(
                    "User must be specified when chroot is enabled".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Parse the listen addresses into SocketAddr objects
    fn socket_addrs(&self) -> EtchDnsResult<Vec<SocketAddr>> {
        let mut addrs = Vec::new();

        for addr_str in &self.listen_addresses {
            let addr = addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!("Invalid socket address {addr_str}: {e}"))
            })?;
            addrs.push(addr);
        }

        Ok(addrs)
    }

    /// Parse the DoH listen addresses into SocketAddr objects
    fn doh_socket_addrs(&self) -> EtchDnsResult<Vec<SocketAddr>> {
        let mut addrs = Vec::new();

        for addr_str in &self.doh_listen_addresses {
            let addr = addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!("Invalid DoH socket address {addr_str}: {e}"))
            })?;
            addrs.push(addr);
        }

        Ok(addrs)
    }

    /// Parse the control server listen addresses into SocketAddr objects
    fn control_socket_addrs(&self) -> EtchDnsResult<Vec<SocketAddr>> {
        let mut addrs = Vec::new();

        for addr_str in &self.control_listen_addresses {
            let addr = addr_str.parse::<SocketAddr>().map_err(|e| {
                EtchDnsError::Other(format!(
                    "Invalid control server socket address {addr_str}: {e}"
                ))
            })?;
            addrs.push(addr);
        }

        Ok(addrs)
    }
}

/// Structure to handle client queries
#[derive(Clone)]
struct ClientQuery {
    /// The data received from the client
    data: Vec<u8>,
    /// The upstream servers to forward the query to
    upstream_servers: Vec<String>,
    /// The server timeout in seconds
    server_timeout: u64,
    /// The maximum DNS packet size
    dns_packet_len_max: usize,
    /// The maximum UDP response size for this client
    max_udp_response_size: usize,
    /// Global statistics tracker
    stats: Option<Arc<SharedStats>>,
    /// Load balancing strategy
    load_balancing_strategy: load_balancer::LoadBalancingStrategy,
    /// Client IP address for EDNS-client-subnet
    client_ip: Option<String>,
    /// Whether EDNS-client-subnet is enabled
    enable_ecs: bool,
    /// IPv4 prefix length for EDNS-client-subnet
    ecs_prefix_v4: u8,
    /// IPv6 prefix length for EDNS-client-subnet
    ecs_prefix_v6: u8,
}

impl ClientQuery {
    /// Create a new ClientQuery with statistics tracking
    fn new(
        data: Vec<u8>,
        upstream_servers: Vec<String>,
        server_timeout: u64,
        dns_packet_len_max: usize,
        stats: Arc<SharedStats>,
        load_balancing_strategy: load_balancer::LoadBalancingStrategy,
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
            enable_ecs: false, // Default to disabled, will be set by the caller
            ecs_prefix_v4: default_ecs_prefix_v4(),
            ecs_prefix_v6: default_ecs_prefix_v6(),
        }
    }

    /// Create a new ClientQuery with statistics tracking and client IP for EDNS-client-subnet
    fn new_with_client_ip(
        data: Vec<u8>,
        upstream_servers: Vec<String>,
        server_timeout: u64,
        dns_packet_len_max: usize,
        stats: Arc<SharedStats>,
        load_balancing_strategy: load_balancer::LoadBalancingStrategy,
        client_ip: String,
        enable_ecs: bool,
        ecs_prefix_v4: u8,
        ecs_prefix_v6: u8,
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
        }
    }

    /// Process the client query by forwarding it to an upstream DNS server
    async fn process(&self) -> EtchDnsResult<Vec<u8>> {
        // Log packet details at debug level
        debug!("Processing query with data: {:?}", self.data);

        // Validate that this is a valid DNS packet
        if let Err(e) = dns_parser::validate_dns_packet(&self.data) {
            // If validation fails, log the error and return without responding
            debug!("Invalid DNS packet: {e}");
            debug!("Dropping invalid DNS packet without response");
            return Err(DnsError::InvalidPacket(format!("Invalid DNS packet: {e}")).into());
        }

        // Choose an upstream server based on the load balancing strategy
        let upstream_server_str = self.select_upstream_server().await?;
        debug!("Selected upstream server: {upstream_server_str}");

        // Parse the upstream server address
        let upstream_addr = upstream_server_str.parse::<SocketAddr>().map_err(|e| {
            DnsError::UpstreamError(format!(
                "Failed to parse upstream server address {upstream_server_str}: {e}"
            ))
        })?;

        // Create a new UDP socket for the upstream connection
        let mut upstream_socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            DnsError::UpstreamError(format!(
                "Failed to bind socket for upstream connection: {e}"
            ))
        })?;
        _ = &mut upstream_socket;
        #[cfg(target_os = "linux")]
        {
            let upstream_socket_std = upstream_socket.into_std().map_err(|e| {
                DnsError::UpstreamError(format!(
                    "Failed to convert upstream socket to standard: {e}"
                ))
            })?;
            let upstream_socket_fd = upstream_socket_std.as_raw_fd();
            let filter = bpfprog!(8,72 0 0 4,53 0 5 17,72 0 0 12,21 0 3 1,72 0 0 18,37 1 0 1,6 0 0 262144,6 0 0 0);
            bpf::attach_filter(upstream_socket_fd, filter).ok();
            upstream_socket_std.set_nonblocking(true).map_err(|e| {
                DnsError::UpstreamError(format!(
                    "Failed to set upstream socket to non-blocking: {e}"
                ))
            })?;
            upstream_socket = UdpSocket::from_std(upstream_socket_std).map_err(|e| {
                DnsError::UpstreamError(format!(
                    "Failed to convert standard socket back to UDP: {e}"
                ))
            })?;
        }
        upstream_socket.set_tos(0x10).ok();

        // If we get here, the packet is valid
        // Set EDNS0 with the configured maximum payload size
        let mut query_data = self.data.clone();
        if let Err(e) =
            dns_parser::set_edns_max_payload_size(&mut query_data, self.dns_packet_len_max as u16)
        {
            error!("Failed to set EDNS maximum payload size: {e}");
            debug!("Continuing with original query without EDNS");
            query_data = self.data.clone(); // Revert to original query data
        } else {
            debug!(
                "Set EDNS maximum payload size to {} bytes",
                self.dns_packet_len_max
            );

            // Add EDNS-client-subnet if enabled and we have a client IP
            if self.enable_ecs {
                if let Some(client_ip) = &self.client_ip {
                    match dns_parser::add_edns_client_subnet(
                        &mut query_data,
                        client_ip,
                        self.ecs_prefix_v4,
                        self.ecs_prefix_v6,
                        self.dns_packet_len_max as u16,
                    ) {
                        Ok(_) => {
                            debug!(
                                "Added EDNS-client-subnet for client IP {} with prefix lengths IPv4:{}/IPv6:{}",
                                client_ip, self.ecs_prefix_v4, self.ecs_prefix_v6
                            );
                        }
                        Err(e) => {
                            error!("Failed to add EDNS-client-subnet: {e}");
                            debug!("Continuing without EDNS-client-subnet");
                        }
                    }
                } else {
                    debug!("EDNS-client-subnet is enabled but no client IP is available");
                }
            }
        }

        // Generate a random transaction ID using a simpler approach
        let random_tid: u16 = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u16)
            ^ 0xABCD; // XOR with a constant for better randomness

        // Store the original transaction ID for verification later
        let original_tid = dns_parser::tid(&query_data);

        // Replace the transaction ID in the query with the random one
        if let Err(e) = dns_parser::set_tid(&mut query_data, random_tid) {
            error!("Failed to set transaction ID: {e}");
            return Err(
                DnsError::InvalidPacket(format!("Failed to set transaction ID: {e}")).into(),
            );
        }

        debug!("Replaced query transaction ID {original_tid} with random ID {random_tid}");

        // Set the initial timeout to half of the server_timeout
        let initial_timeout = std::cmp::max(1, self.server_timeout / 2);
        debug!("Using initial timeout of {initial_timeout} seconds");

        // Receive buffer
        let mut buf = vec![0u8; self.dns_packet_len_max]; // Use the configured maximum DNS packet size

        // Start timing the request
        let start_time = std::time::Instant::now();

        // First attempt
        debug!("Sending query to upstream server (first attempt): {upstream_addr}");
        upstream_socket
            .send_to(&query_data, &upstream_addr)
            .await
            .map_err(|e| {
                DnsError::UpstreamError(format!(
                    "Failed to send query to upstream server {upstream_addr}: {e}"
                ))
            })?;

        // Wait for the response with the initial timeout
        let initial_timeout_duration = tokio::time::Duration::from_secs(initial_timeout);
        let recv_future = upstream_socket.recv_from(&mut buf);

        match tokio::time::timeout(initial_timeout_duration, recv_future).await {
            Ok(Ok((len, _))) => {
                // Successfully received a response within the initial timeout
                let response_time = start_time.elapsed();
                debug!(
                    "Received response of size {len} bytes from upstream server (first attempt): {upstream_addr} in {response_time:?}"
                );

                // Record the successful response in stats if available
                if let Some(stats) = &self.stats {
                    if let Ok(addr) = upstream_addr.to_string().parse() {
                        // Use a reference to avoid cloning
                        let stats_ref = Arc::clone(stats);
                        tokio::spawn(async move {
                            stats_ref.record_success(addr, response_time).await;
                        });
                    }
                }

                // Process the response
                return process_response(&buf[..len], random_tid, upstream_addr).await;
            }
            Ok(Err(e)) => {
                // Socket error
                error!("Failed to receive response from upstream server {upstream_addr}: {e}");

                // Record the failure in stats if available
                if let Some(stats) = &self.stats {
                    if let Ok(addr) = upstream_addr.to_string().parse() {
                        // Use a reference to avoid cloning
                        let stats_ref = Arc::clone(stats);
                        tokio::spawn(async move {
                            stats_ref.record_failure(addr).await;
                        });
                    }
                }

                Err(DnsError::UpstreamError(format!(
                    "Failed to receive response from upstream server {upstream_addr}: {e}"
                ))
                .into())
            }
            Err(_) => {
                // Timeout occurred, try again
                debug!(
                    "Timeout waiting for response from upstream server after {initial_timeout} seconds (retrying): {upstream_addr}"
                );

                // Record the timeout in stats if available
                if let Some(stats) = &self.stats {
                    if let Ok(addr) = upstream_addr.to_string().parse() {
                        // Use a reference to avoid cloning
                        let stats_ref = Arc::clone(stats);
                        tokio::spawn(async move {
                            stats_ref.record_timeout(addr).await;
                        });
                    }
                }

                // Second attempt
                debug!("Sending query to upstream server (retry attempt): {upstream_addr}");
                upstream_socket
                    .send_to(&query_data, &upstream_addr)
                    .await
                    .map_err(|e| {
                        DnsError::UpstreamError(format!(
                            "Failed to send retry query to upstream server {upstream_addr}: {e}"
                        ))
                    })?;

                // Wait for the response with the remaining timeout
                let remaining_timeout = self.server_timeout - initial_timeout;
                let remaining_timeout_duration =
                    tokio::time::Duration::from_secs(remaining_timeout);
                let recv_future = upstream_socket.recv_from(&mut buf);

                match tokio::time::timeout(remaining_timeout_duration, recv_future).await {
                    Ok(Ok((len, _))) => {
                        // Successfully received a response on the retry
                        debug!(
                            "Received response of size {len} bytes from upstream server (retry attempt): {upstream_addr}"
                        );

                        // Process the response
                        process_response(&buf[..len], random_tid, upstream_addr).await
                    }
                    Ok(Err(e)) => {
                        // Socket error on retry
                        error!(
                            "Failed to receive response from upstream server on retry {upstream_addr}: {e}"
                        );
                        Err(DnsError::UpstreamError(format!(
                            "Failed to receive response from upstream server on retry {upstream_addr}: {e}"
                        ))
                        .into())
                    }
                    Err(_) => {
                        // Timeout on retry
                        debug!(
                            "Timeout waiting for response from upstream server on retry after {remaining_timeout} seconds: {upstream_addr}"
                        );

                        // Record the timeout in stats if available
                        if let Some(stats) = &self.stats {
                            if let Ok(addr) = upstream_addr.to_string().parse() {
                                // Use a reference to avoid cloning
                                let stats_ref = Arc::clone(stats);
                                tokio::spawn(async move {
                                    stats_ref.record_timeout(addr).await;
                                });
                            }
                        }

                        // Return timeout error after both attempts failed
                        Err(DnsError::UpstreamTimeout.into())
                    }
                }
            }
        }
    }

    /// Select an upstream server based on the load balancing strategy
    async fn select_upstream_server(&self) -> EtchDnsResult<String> {
        let upstream_servers = &self.upstream_servers;
        if upstream_servers.is_empty() {
            return Err(
                DnsError::UpstreamError("No upstream servers configured".to_string()).into(),
            );
        }

        // Use the load balancer to select a server
        load_balancer::select_upstream_server(
            upstream_servers,
            self.load_balancing_strategy,
            self.stats.as_ref(),
        )
        .await
        .map(|s| s.to_string()) // Convert &String to String
        .ok_or_else(|| {
            EtchDnsError::DnsProcessingError(DnsError::UpstreamError(
                "Failed to select upstream server".to_string(),
            ))
        })
    }
}

/// Process a DNS response
async fn process_response(
    response_data: &[u8],
    expected_tid: u16,
    upstream_addr: SocketAddr,
) -> EtchDnsResult<Vec<u8>> {
    // Verify the transaction ID in the response
    let response_tid = dns_parser::tid(response_data);
    if response_tid != expected_tid {
        debug!("Transaction ID mismatch: expected {expected_tid}, got {response_tid}");
        return Err(
            DnsError::UpstreamError("Transaction ID mismatch in response".to_string()).into(),
        );
    }

    debug!("Verified response transaction ID: {response_tid}");

    // Validate that the response is a valid DNS response
    if let Err(e) = dns_parser::validate_dns_response(response_data) {
        debug!("Invalid DNS response: {e}");
        return Err(DnsError::UpstreamError(format!("Invalid DNS response: {e}")).into());
    }

    // Check if the response is truncated (TC bit set)
    if dns_parser::is_truncated(response_data) {
        debug!("Received truncated DNS response (TC bit set), retrying with TCP");

        // Retry the query using TCP
        match retry_with_tcp(response_data, expected_tid, upstream_addr).await {
            Ok(tcp_response) => {
                debug!("Successfully received complete response via TCP");
                return Ok(tcp_response);
            }
            Err(e) => {
                // Log the error but still return the truncated UDP response
                // This is better than returning nothing
                warn!(
                    "Failed to get complete response via TCP: {e}, returning truncated UDP response"
                );
            }
        }
    }

    Ok(response_data.to_vec())
}

/// Retry a DNS query using TCP when the UDP response is truncated
async fn retry_with_tcp(
    udp_response: &[u8],
    expected_tid: u16,
    upstream_addr: SocketAddr,
) -> EtchDnsResult<Vec<u8>> {
    // Recover a proper query from the truncated response
    let query_data = match dns_parser::recover_question_from_response(udp_response) {
        Ok(data) => data,
        Err(e) => {
            return Err(DnsError::InvalidPacket(format!(
                "Failed to recover question from response: {e}"
            ))
            .into());
        }
    };

    debug!("Created TCP query from truncated UDP response");

    // Create a TCP connection to the upstream server
    debug!("Connecting to upstream DNS server via TCP: {upstream_addr}");
    let mut tcp_stream = match tokio::net::TcpStream::connect(upstream_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            return Err(DnsError::UpstreamError(format!(
                "Failed to connect to upstream server via TCP: {e}"
            ))
            .into());
        }
    };

    // Prepare the DNS query for TCP (prepend 2-byte length)
    let query_len = query_data.len() as u16;
    let mut tcp_query = Vec::with_capacity(query_data.len() + 2);
    tcp_query.push((query_len >> 8) as u8);
    tcp_query.push(query_len as u8);
    tcp_query.extend_from_slice(&query_data);

    // Send the query
    debug!("Sending DNS query via TCP to {upstream_addr}");
    if let Err(e) = tcp_stream.write_all(&tcp_query).await {
        return Err(
            DnsError::UpstreamError(format!("Failed to send DNS query via TCP: {e}")).into(),
        );
    }

    // Read the response length (2 bytes)
    // Since this is only 2 bytes, we can use read_exact() here
    // The risk of DoS is minimal for such a small read
    let mut length_buf = [0u8; 2];
    if let Err(e) = tcp_stream.read_exact(&mut length_buf).await {
        return Err(DnsError::UpstreamError(format!(
            "Failed to read DNS response length via TCP: {e}"
        ))
        .into());
    }

    // Calculate the response length
    let response_len = ((length_buf[0] as usize) << 8) | (length_buf[1] as usize);
    if !(dns_parser::DNS_PACKET_LEN_MIN..=dns_parser::DNS_MAX_PACKET_SIZE).contains(&response_len) {
        return Err(DnsError::UpstreamError(format!(
            "Invalid DNS response length via TCP: {response_len}"
        ))
        .into());
    }

    // Read the response using multiple read() calls to prevent DoS attacks
    // where a malicious client sends one byte at a time
    let mut response_buf = vec![0u8; response_len];
    let mut total_bytes_read = 0;

    // Define minimum read size (except for the last read)
    let min_read_size = 512;

    while total_bytes_read < response_len {
        let bytes_remaining = response_len - total_bytes_read;

        // Read into the appropriate slice of the buffer
        let read_result = tcp_stream.read(&mut response_buf[total_bytes_read..]).await;

        match read_result {
            Ok(bytes_read) => {
                if bytes_read == 0 {
                    // Connection closed prematurely
                    return Err(DnsError::UpstreamError(format!(
                        "TCP connection closed unexpectedly after reading {total_bytes_read} of {response_len} bytes"
                    ))
                    .into());
                }

                // Check if we're getting small reads (potential DoS)
                // Only enforce minimum read size if we're not near the end
                if bytes_read < min_read_size && bytes_remaining > min_read_size {
                    debug!(
                        "Small TCP read detected ({bytes_read} bytes). This could be inefficient."
                    );
                }

                total_bytes_read += bytes_read;
                debug!("Read {bytes_read} bytes, total so far: {total_bytes_read}/{response_len}");
            }
            Err(e) => {
                return Err(DnsError::UpstreamError(format!(
                    "Failed to read DNS response via TCP after {total_bytes_read} of {response_len} bytes: {e}"
                ))
                .into());
            }
        }
    }

    // Verify the transaction ID in the response
    let response_tid = dns_parser::tid(&response_buf);
    if response_tid != expected_tid {
        debug!("TCP response transaction ID mismatch: expected {expected_tid}, got {response_tid}");
        return Err(
            DnsError::UpstreamError("Transaction ID mismatch in TCP response".to_string()).into(),
        );
    }

    // Validate that the response is a valid DNS response
    if let Err(e) = dns_parser::validate_dns_response(&response_buf) {
        debug!("Invalid DNS TCP response: {e}");
        return Err(DnsError::UpstreamError(format!("Invalid DNS TCP response: {e}")).into());
    }

    debug!("Successfully received DNS response via TCP, size: {response_len}");
    Ok(response_buf)
}

/// Trait for different types of clients
#[async_trait]
trait Client {
    async fn process_query(&self);
}

/// Structure to handle UDP clients
#[derive(Clone)]
struct UDPClient {
    /// The UDP socket to use for sending responses
    socket: Arc<UdpSocket>,

    /// The client's address
    addr: SocketAddr,

    /// The client query
    query: ClientQuery,

    /// The query manager for aggregating identical DNS queries
    query_manager: Arc<QueryManager>,
}

/// Structure to handle TCP clients
#[derive(Clone)]
struct TCPClient {
    /// The client's address
    addr: SocketAddr,

    /// The client query
    query: ClientQuery,

    /// The query manager for aggregating identical DNS queries
    query_manager: Arc<QueryManager>,

    /// The TCP stream to write responses to
    stream: Arc<Mutex<TcpStream>>,
}

impl UDPClient {
    /// Create a new UDPClient
    fn new(
        socket: Arc<UdpSocket>,
        data: Vec<u8>,
        addr: SocketAddr,
        upstream_servers: Vec<String>,
        query_manager: Arc<QueryManager>,
    ) -> Self {
        // Get the server_timeout and dns_packet_len_max from the query_manager
        let server_timeout = query_manager.get_server_timeout();
        let dns_packet_len_max = query_manager.get_dns_packet_len_max();

        // Get the stats from the query manager
        let stats = query_manager
            .get_stats()
            .expect("QueryManager should have stats");

        // Get the load balancing strategy from the query manager
        let load_balancing_strategy = query_manager.get_load_balancing_strategy();

        // Get the ECS configuration from the query manager
        let enable_ecs = query_manager.get_enable_ecs();
        let ecs_prefix_v4 = query_manager.get_ecs_prefix_v4();
        let ecs_prefix_v6 = query_manager.get_ecs_prefix_v6();

        // Extract client IP (without port) for EDNS-client-subnet
        let client_ip = addr.ip().to_string();

        // Create the client query with client IP for EDNS-client-subnet
        let query = ClientQuery::new_with_client_ip(
            data,
            upstream_servers,
            server_timeout,
            dns_packet_len_max,
            stats,
            load_balancing_strategy,
            client_ip,
            enable_ecs,
            ecs_prefix_v4,
            ecs_prefix_v6,
        );

        Self {
            socket,
            addr,
            query,
            query_manager,
        }
    }
}

impl TCPClient {
    /// Create a new TCPClient
    fn new(
        data: Vec<u8>,
        addr: SocketAddr,
        upstream_servers: Vec<String>,
        query_manager: Arc<QueryManager>,
        stream: Arc<Mutex<TcpStream>>,
    ) -> Self {
        // Get the server_timeout and dns_packet_len_max from the query_manager
        let server_timeout = query_manager.get_server_timeout();
        let dns_packet_len_max = query_manager.get_dns_packet_len_max();

        // Get the stats from the query manager
        let stats = query_manager
            .get_stats()
            .expect("QueryManager should have stats");

        // Get the load balancing strategy from the query manager
        let load_balancing_strategy = query_manager.get_load_balancing_strategy();

        // Get the ECS configuration from the query manager
        let enable_ecs = query_manager.get_enable_ecs();
        let ecs_prefix_v4 = query_manager.get_ecs_prefix_v4();
        let ecs_prefix_v6 = query_manager.get_ecs_prefix_v6();

        // Extract client IP (without port) for EDNS-client-subnet
        let client_ip = addr.ip().to_string();

        // Create the client query with client IP for EDNS-client-subnet
        let query = ClientQuery::new_with_client_ip(
            data,
            upstream_servers,
            server_timeout,
            dns_packet_len_max,
            stats,
            load_balancing_strategy,
            client_ip,
            enable_ecs,
            ecs_prefix_v4,
            ecs_prefix_v6,
        );

        Self {
            addr,
            query,
            query_manager,
            stream,
        }
    }
}

/// Process a TCP connection
///
/// This function reads DNS queries from a TCP connection and processes them.
/// It handles the TCP-specific aspects of DNS, including the 2-byte length field.
///
/// # Arguments
///
/// * `stream` - The TCP stream to read from and write to
/// * `addr` - The client's address
/// * `upstream_servers` - The upstream DNS servers to forward queries to
/// * `query_manager` - The query manager for aggregating identical DNS queries
/// * `tcp_clients_slab` - The slab for storing TCP clients
/// * `dns_packet_len_max` - The maximum DNS packet size
/// * `server_timeout` - The timeout for TCP connections in seconds
///
/// # Returns
///
/// This function returns when the TCP connection is closed or times out.
async fn process_tcp_connection(
    stream: TcpStream,
    addr: SocketAddr,
    upstream_servers: Vec<String>,
    query_manager: Arc<QueryManager>,
    tcp_clients_slab: Arc<Mutex<Slab<TCPClient>>>,
    dns_packet_len_max: usize,
    server_timeout: u64,
) {
    // Create a shared stream for the client
    let stream_arc = Arc::new(Mutex::new(stream));

    // Create a buffer for reading the length field
    let mut len_buf = [0u8; 2];

    // Set the timeout duration
    let timeout_duration = Duration::from_secs(server_timeout);

    // Main loop for processing queries on this connection
    loop {
        // Read the 2-byte length field with timeout
        // Since this is only 2 bytes, we can use read_exact() here
        // The risk of DoS is minimal for such a small read
        let read_result = tokio::time::timeout(timeout_duration, async {
            let mut stream = stream_arc.lock().await;
            stream.read_exact(&mut len_buf).await
        })
        .await;

        // Check if the operation timed out
        match read_result {
            Ok(read_exact_result) => {
                match read_exact_result {
                    Ok(_) => {
                        // Convert the length field to a u16
                        let len = ((len_buf[0] as u16) << 8) | (len_buf[1] as u16);
                        debug!("TCP client {addr} sent a query of length {len}");

                        // Check if the length is valid
                        if len as usize > dns_packet_len_max {
                            error!(
                                "TCP client {addr} sent a query with length {len} which exceeds the maximum of {dns_packet_len_max}"
                            );
                            break;
                        }

                        // Read the query with timeout using multiple read() calls
                        // to prevent DoS attacks where a malicious client sends one byte at a time
                        let query_read_result = tokio::time::timeout(timeout_duration, async {
                            let mut stream = stream_arc.lock().await;
                            let mut query_buf = vec![0u8; len as usize];
                            let mut total_bytes_read = 0;
                            let min_read_size = 512;

                            while total_bytes_read < len as usize {
                                let bytes_remaining = len as usize - total_bytes_read;

                                // Read into the appropriate slice of the buffer
                                match stream.read(&mut query_buf[total_bytes_read..]).await {
                                    Ok(bytes_read) => {
                                        if bytes_read == 0 {
                                            // Connection closed prematurely
                                            return (Err(std::io::Error::new(
                                                std::io::ErrorKind::UnexpectedEof,
                                                format!("TCP connection closed unexpectedly after reading {total_bytes_read} of {len} bytes")
                                            )), query_buf);
                                        }

                                        // Check if we're getting small reads (potential DoS)
                                        // Only enforce minimum read size if we're not near the end
                                        if bytes_read < min_read_size && bytes_remaining > min_read_size {
                                            debug!(
                                                "Small TCP read detected from client {addr} ({bytes_read} bytes). This could be inefficient."
                                            );
                                        }

                                        total_bytes_read += bytes_read;
                                        debug!("Read {bytes_read} bytes from client {addr}, total so far: {total_bytes_read}/{len}");
                                    },
                                    Err(e) => {
                                        return (Err(e), query_buf);
                                    }
                                }
                            }

                            (Ok(()), query_buf)
                        })
                        .await;

                        match query_read_result {
                            Ok((read_result, query_buf)) => {
                                match read_result {
                                    Ok(_) => {
                                        debug!("Read {len} bytes from TCP client {addr}");

                                        // Create a new TCPClient without cloning the query buffer
                                        let client = TCPClient::new(
                                            query_buf,
                                            addr,
                                            upstream_servers.clone(),
                                            query_manager.clone(),
                                            stream_arc.clone(),
                                        );

                                        // Add the client to the slab
                                        let client_slot = {
                                            let mut slab = tcp_clients_slab.lock().await;

                                            // If the slab is full, remove the oldest entry
                                            if slab.is_full() && slab.pop_back().is_some() {
                                                debug!("TCP slab is full, removing oldest client");
                                            }

                                            // Add the new client to the front of the slab
                                            let slot = slab
                                                .push_front(client.clone())
                                                .expect("Failed to add TCP client to slab");

                                            // Increment the active TCP clients counter
                                            if let Some(stats) = &client.query.stats {
                                                stats.increment_active_tcp_clients().await;
                                            }

                                            debug!(
                                                "Added TCP client to slab with slot {}, slab size: {}",
                                                slot,
                                                slab.len()
                                            );
                                            slot
                                        };

                                        // Process the client query directly
                                        client.process_query().await;
                                        debug!("Completed processing task for TCP client {addr}");

                                        // Remove the client from the slab
                                        {
                                            let mut slab = tcp_clients_slab.lock().await;

                                            // Remove the client by slot
                                            if let Err(e) = slab.remove(client_slot) {
                                                error!(
                                                    "Failed to remove TCP client from slab: {e}"
                                                );
                                            } else {
                                                // Decrement the active TCP clients counter
                                                if let Some(stats) = &client.query.stats {
                                                    stats.decrement_active_tcp_clients().await;
                                                }

                                                debug!(
                                                    "Removed TCP client from slab with slot {}, slab size: {}",
                                                    client_slot,
                                                    slab.len()
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to read query from TCP client {addr}: {e}");
                                        break;
                                    }
                                }
                            }
                            Err(_) => {
                                debug!(
                                    "TCP connection from {addr} timed out after {server_timeout} seconds"
                                );
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        // If we get an EOF, the client closed the connection
                        if e.kind() == std::io::ErrorKind::UnexpectedEof {
                            debug!("TCP client {addr} closed the connection");
                        } else {
                            error!("Failed to read length from TCP client {addr}: {e}");
                        }
                        break;
                    }
                }
            }
            Err(_) => {
                debug!("TCP connection from {addr} timed out after {server_timeout} seconds");
                break;
            }
        }
    }

    debug!("TCP connection handler for client {addr} exiting");
}

// Use the DnsQueryProcessor trait from dns_processor.rs

// Implement the DnsQueryProcessor trait for both client types
impl DnsQueryProcessor for TCPClient {}
impl DnsQueryProcessor for UDPClient {}

#[async_trait]
impl Client for TCPClient {
    async fn process_query(&self) {
        // Process the DNS query
        let client_addr = self.addr.to_string();
        if let Some((response_data, _)) = self
            .process_dns_query(
                &self.query.data,
                &client_addr,
                "TCP",
                &self.query_manager,
                &self.query.upstream_servers,
                self.query.server_timeout,
                self.query.dns_packet_len_max,
                self.query.stats.clone(),
                self.query.load_balancing_strategy,
            )
            .await
        {
            // For TCP, we need to prepend the 2-byte length field
            let response_len = response_data.len() as u16;
            let mut tcp_response = Vec::with_capacity(response_data.len() + 2);
            tcp_response.push((response_len >> 8) as u8);
            tcp_response.push(response_len as u8);
            tcp_response.extend_from_slice(&response_data);

            // Send the response back to the client
            let mut stream = self.stream.lock().await;
            match stream.write_all(&tcp_response).await {
                Ok(_) => {
                    debug!(
                        "Sent {} bytes back to TCP client {}",
                        response_data.len(),
                        self.addr
                    );
                    debug!("Response successfully sent to client {}", self.addr);
                }
                Err(e) => {
                    error!("Failed to send response to TCP client {}: {}", self.addr, e);
                    debug!("Error details: {e:?}");
                }
            }
        }
    }
}

#[async_trait]
impl Client for UDPClient {
    async fn process_query(&self) {
        // Process the DNS query
        let client_addr = self.addr.to_string();
        if let Some((mut response_data, _)) = self
            .process_dns_query(
                &self.query.data,
                &client_addr,
                "UDP",
                &self.query_manager,
                &self.query.upstream_servers,
                self.query.server_timeout,
                self.query.dns_packet_len_max,
                self.query.stats.clone(),
                self.query.load_balancing_strategy,
            )
            .await
        {
            // Check if the response exceeds the maximum UDP response size
            if response_data.len() > self.query.max_udp_response_size {
                debug!(
                    "Response size ({} bytes) exceeds maximum UDP response size ({} bytes), truncating",
                    response_data.len(),
                    self.query.max_udp_response_size
                );

                // Truncate the response
                match dns_parser::truncate_dns_packet(
                    &response_data,
                    Some(self.query.max_udp_response_size),
                    false,
                ) {
                    Ok(truncated_data) => {
                        debug!(
                            "Truncated response from {} bytes to {} bytes",
                            response_data.len(),
                            truncated_data.len()
                        );
                        response_data = truncated_data;
                    }
                    Err(e) => {
                        error!("Failed to truncate response: {e}");
                        debug!("Error details: {e:?}");
                        // Continue with the original response
                    }
                }
            }

            // Send the response back to the client
            match self.socket.send_to(&response_data, self.addr).await {
                Ok(bytes_sent) => {
                    debug!("Sent {} bytes back to UDP client {}", bytes_sent, self.addr);
                    debug!("Response successfully sent to client {}", self.addr);
                }
                Err(e) => {
                    error!("Failed to send response to UDP client {}: {}", self.addr, e);
                    debug!("Error details: {e:?}");
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> EtchDnsResult<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Load configuration from file
    let config = Config::from_file(&args.config)?;

    // Initialize the logger with the configured log level
    let log_level = config.log_level.to_lowercase();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&log_level)).init();

    debug!("Command line arguments: {args:?}");
    debug!("Loaded configuration: {config:?}");

    // Log startup information at INFO level
    info!("Starting EtchDNS server");
    info!("Log level: {}", config.log_level);

    // Log listening addresses
    for addr in &config.listen_addresses {
        info!("Listening on: {addr} (UDP/TCP)");
    }

    // Log DoH addresses if configured
    if !config.doh_listen_addresses.is_empty() {
        for addr in &config.doh_listen_addresses {
            info!("Listening on: {addr} (DoH)");
        }
    } else {
        info!("DoH server is disabled");
    }

    // Log metrics server if configured
    if let Some(addr) = &config.metrics_address {
        info!(
            "Metrics server enabled on: {}, path: {}",
            addr, config.metrics_path
        );
    } else {
        info!("Metrics server is disabled");
    }

    // Log cache information
    info!("DNS cache size: {} entries", config.cache_size);

    // Log load balancing strategy
    info!(
        "Load balancing strategy: {}",
        config.load_balancing_strategy
    );

    // Log domain filtering information
    if let Some(file) = &config.allowed_zones_file {
        info!("Domain filtering enabled with allowed zones file: {file}");
    }

    // Log NX domains information
    if let Some(file) = &config.nx_zones_file {
        info!("NX domains filtering enabled with file: {file}");
    }

    // Log rate limiting information
    if config.udp_rate_limit_window > 0 {
        info!(
            "UDP rate limiting: {} queries per {} seconds",
            config.udp_rate_limit_count, config.udp_rate_limit_window
        );
    } else {
        info!("UDP rate limiting is disabled");
    }

    if config.tcp_rate_limit_window > 0 {
        info!(
            "TCP rate limiting: {} queries per {} seconds",
            config.tcp_rate_limit_count, config.tcp_rate_limit_window
        );
    } else {
        info!("TCP rate limiting is disabled");
    }

    if !config.doh_listen_addresses.is_empty() && config.doh_rate_limit_window > 0 {
        info!(
            "DoH rate limiting: {} queries per {} seconds",
            config.doh_rate_limit_count, config.doh_rate_limit_window
        );
    }

    // Get the socket addresses to bind to
    let socket_addrs = config.socket_addrs()?;

    // Create vectors to store all the sockets
    let mut udp_sockets = Vec::new();
    let mut tcp_listeners = Vec::new();

    // Bind to each address
    for socket_addr in &socket_addrs {
        // Bind UDP socket
        let udp_socket = UdpSocket::bind(socket_addr)
            .await
            .map_err(EtchDnsError::SocketBindError)?;
        info!(
            "Listening on UDP: {}",
            udp_socket
                .local_addr()
                .map_err(EtchDnsError::SocketBindError)?
        );

        // Create a shareable UDP socket
        udp_sockets.push(Arc::new(udp_socket));

        // Bind TCP listener
        let tcp_listener = tokio::net::TcpListener::bind(socket_addr)
            .await
            .map_err(EtchDnsError::SocketBindError)?;
        info!(
            "Listening on TCP: {}",
            tcp_listener
                .local_addr()
                .map_err(EtchDnsError::SocketBindError)?
        );

        // Create a shareable TCP listener
        tcp_listeners.push(Arc::new(tcp_listener));
    }

    // Log the buffer capacity
    debug!(
        "Using buffer capacity of {} bytes for each socket",
        config.dns_packet_len_max
    );

    // Create slabs for clients with the configured maximum sizes
    let max_udp_clients = config.max_udp_clients;
    let max_tcp_clients = config.max_tcp_clients;
    debug!(
        "Using a maximum of {max_udp_clients} UDP clients and {max_tcp_clients} TCP clients in the slabs"
    );
    let udp_clients_slab = Arc::new(Mutex::new(
        Slab::with_capacity(max_udp_clients).expect("Failed to create UDP clients slab"),
    ));
    let tcp_clients_slab = Arc::new(Mutex::new(
        Slab::with_capacity(max_tcp_clients).expect("Failed to create TCP clients slab"),
    ));

    // Create global statistics tracker
    let global_stats = Arc::new(SharedStats::new());
    debug!("Created global statistics tracker");

    // Create a Hooks structure
    let mut hooks = Arc::new(hooks::SharedHooks::new());
    debug!("Created hooks structure");

    // Create a query logger if configured
    let query_logger = Arc::new(query_logger::QueryLogger::new(
        config.query_log_file.clone(),
        config.query_log_include_timestamp,
        config.query_log_include_client_addr,
        config.query_log_include_query_type,
        config.query_log_include_query_class,
    ));

    if let Some(log_file) = &config.query_log_file {
        info!("Query logging enabled to file: {log_file}");
    }

    // Load WebAssembly hooks if specified and hooks feature is enabled
    if let Some(wasm_file) = &config.hooks_wasm_file {
        info!("Loading WebAssembly hooks from file: {wasm_file}");
        #[cfg(feature = "hooks")]
        {
            info!(
                "WebAssembly WASI support is {}",
                if config.hooks_wasm_wasi {
                    "enabled"
                } else {
                    "disabled"
                }
            );
        }
        match hooks::Hooks::with_wasm_file(wasm_file, config.hooks_wasm_wasi) {
            Ok(wasm_hooks) => {
                // Replace the default hooks with the WebAssembly hooks
                hooks = Arc::new(hooks::SharedHooks::with_hooks(wasm_hooks));
                debug!("Successfully loaded WebAssembly hooks");
            }
            Err(e) => {
                error!("Failed to load WebAssembly hooks: {e}");
                // Continue with default hooks
            }
        }
    }

    // Create a DNS cache with the configured capacity
    let cache_capacity = config.cache_size;
    let dns_cache = Arc::new(cache::create_dns_cache(cache_capacity));
    debug!("Created DNS cache with capacity of {cache_capacity} entries");

    // Create rate limiters for UDP and TCP if enabled
    let udp_rate_limiter = if config.udp_rate_limit_window > 0 {
        let limiter = Arc::new(rate_limiter::RateLimiter::new(
            config.udp_rate_limit_window,
            config.udp_rate_limit_count,
            config.udp_rate_limit_max_clients,
        ));
        debug!(
            "Created UDP rate limiter with window of {} seconds, limit of {} queries per client IP, and max of {} client IPs",
            config.udp_rate_limit_window,
            config.udp_rate_limit_count,
            config.udp_rate_limit_max_clients
        );
        Some(limiter)
    } else {
        debug!("UDP rate limiting is disabled");
        None
    };

    let tcp_rate_limiter = if config.tcp_rate_limit_window > 0 {
        let limiter = Arc::new(rate_limiter::RateLimiter::new(
            config.tcp_rate_limit_window,
            config.tcp_rate_limit_count,
            config.tcp_rate_limit_max_clients,
        ));
        debug!(
            "Created TCP rate limiter with window of {} seconds, limit of {} queries per client IP, and max of {} client IPs",
            config.tcp_rate_limit_window,
            config.tcp_rate_limit_count,
            config.tcp_rate_limit_max_clients
        );
        Some(limiter)
    } else {
        debug!("TCP rate limiting is disabled");
        None
    };

    // Create a rate limiter for DoH if enabled
    let doh_rate_limiter = if config.doh_rate_limit_window > 0 {
        let limiter = Arc::new(rate_limiter::RateLimiter::new(
            config.doh_rate_limit_window,
            config.doh_rate_limit_count,
            config.doh_rate_limit_max_clients,
        ));
        debug!(
            "Created DoH rate limiter with window of {} seconds, limit of {} queries per client IP, and max of {} client IPs",
            config.doh_rate_limit_window,
            config.doh_rate_limit_count,
            config.doh_rate_limit_max_clients
        );
        Some(limiter)
    } else {
        debug!("DoH rate limiting is disabled");
        None
    };

    // Create a query manager for aggregating identical DNS queries
    let max_inflight_queries = config.max_inflight_queries;
    let server_timeout = config.server_timeout;
    let dns_packet_len_max = config.dns_packet_len_max;

    // Parse the load balancing strategy
    let load_balancing_strategy = config
        .load_balancing_strategy
        .parse::<load_balancer::LoadBalancingStrategy>()
        .unwrap_or_else(|_| {
            warn!(
                "Invalid load balancing strategy: {}, using fastest",
                config.load_balancing_strategy
            );
            load_balancer::LoadBalancingStrategy::Fastest
        });

    let mut query_manager = QueryManager::new(
        max_inflight_queries,
        server_timeout,
        dns_packet_len_max,
        global_stats.clone(),
        load_balancing_strategy,
        config.authoritative_dns,
        config.serve_stale_grace_time,
        config.serve_stale_ttl,
        config.negative_cache_ttl,
        config.min_cache_ttl,
        config.enable_ecs,
        config.ecs_prefix_v4,
        config.ecs_prefix_v6,
    );

    // Set the DNS cache in the query manager
    query_manager.set_cache((*dns_cache).clone());

    // Set the hooks in the query manager
    query_manager.set_hooks(hooks.clone());

    // Set the query logger in the query manager
    query_manager.set_query_logger(query_logger.clone());

    // Load allowed zones if configured
    if let Some(allowed_zones_file) = &config.allowed_zones_file {
        match allowed_zones::AllowedZones::load_from_file(allowed_zones_file) {
            Ok(zones) => {
                let zone_count = zones.len();
                query_manager.set_allowed_zones(zones);
                info!("Loaded {zone_count} allowed zones from {allowed_zones_file}");
            }
            Err(e) => {
                error!("Failed to load allowed zones from {allowed_zones_file}: {e}");
                return Err(EtchDnsError::ConfigParseError(format!(
                    "Failed to load allowed zones file: {e}"
                )));
            }
        }
    }

    // Load nonexistent zones if configured
    if let Some(nx_zones_file) = &config.nx_zones_file {
        match nx_zones::NxZones::load_from_file(nx_zones_file) {
            Ok(zones) => {
                let zone_count = zones.len();
                query_manager.set_nx_zones(zones);
                info!("Loaded {zone_count} nonexistent zones from {nx_zones_file}");
            }
            Err(e) => {
                error!("Failed to load nonexistent zones from {nx_zones_file}: {e}");
                return Err(EtchDnsError::ConfigParseError(format!(
                    "Failed to load nonexistent zones file: {e}"
                )));
            }
        }
    }

    let query_manager = Arc::new(query_manager);
    debug!(
        "Created query manager with a maximum of {max_inflight_queries} in-flight queries, {server_timeout} second timeout, {dns_packet_len_max} byte packet size, and '{load_balancing_strategy}' load balancing strategy"
    );

    // Drop privileges if configured
    if let Some(username) = &config.user {
        info!("Dropping privileges to user: {username}");

        // Create a new privdrop instance
        let pd = privdrop::PrivDrop::default();

        // Build the privilege drop configuration
        let mut pd = pd.user(username);

        // Set the group if specified
        if let Some(group) = &config.group {
            info!("Using group: {group}");
            pd = pd.group(group);
        }

        // Set chroot if specified
        if let Some(chroot_dir) = &config.chroot {
            info!("Using chroot directory: {chroot_dir}");
            pd = pd.chroot(chroot_dir);
        }

        // Apply the privilege drop
        match pd.apply() {
            Ok(_) => {
                info!("Successfully dropped privileges");
            }
            Err(e) => {
                let error_msg = format!("Failed to drop privileges: {e}");
                error!("{error_msg}");
                return Err(EtchDnsError::PrivilegeDropError(error_msg));
            }
        }
    } else {
        warn!(
            "Running with full privileges. Consider setting 'user' in config.toml for better security."
        );
    }

    // Create a vector of tasks
    let mut tasks = Vec::new();

    // Start the server prober if probe_interval is greater than 0
    if config.probe_interval > 0 {
        info!(
            "Starting server prober with interval of {} seconds and timeout of {} seconds",
            config.probe_interval, config.server_timeout
        );

        // Clone the values we need for the prober
        let upstream_servers = config.upstream_servers.clone();
        let stats = global_stats.clone();
        let probe_interval = config.probe_interval;
        let server_timeout = config.server_timeout;

        // Create a task for the server prober
        let prober_task = tokio::spawn(async move {
            // Create a ticker that fires at the specified interval
            let mut interval = tokio::time::interval(Duration::from_secs(probe_interval));

            loop {
                // Wait for the next tick
                interval.tick().await;

                // Probe all servers
                debug!("Probing all upstream DNS servers");

                for server in &upstream_servers {
                    // Parse the server address
                    match server.parse::<SocketAddr>() {
                        Ok(addr) => {
                            // Probe the server
                            match probe_server(addr, server_timeout).await {
                                Ok(response_time) => {
                                    debug!("Probe to {addr} completed in {response_time:.2?}");

                                    // Record the success in stats
                                    stats.record_success(addr, response_time).await;
                                }
                                Err(e) => {
                                    warn!("Probe to {addr} failed: {e}");

                                    // Record the failure in stats
                                    stats.record_failure(addr).await;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse server address {server}: {e}");
                        }
                    }
                }
            }
        });

        // Add the prober task to the list of tasks
        tasks.push(prober_task);
    }

    // Start the HTTP metrics server if configured
    if let Some(metrics_addr) = &config.metrics_address {
        // Parse the metrics address
        let metrics_addr = metrics_addr.parse::<SocketAddr>().map_err(|e| {
            EtchDnsError::Other(format!("Invalid metrics address {metrics_addr}: {e}"))
        })?;

        // Clone the values we need for the metrics server
        let metrics_path = config.metrics_path.clone();
        let stats = global_stats.clone();
        let max_metrics_connections = config.max_metrics_connections;

        // Create a task for the metrics server
        let metrics_task = tokio::spawn(async move {
            info!("Starting metrics server on {metrics_addr}, path: {metrics_path}");

            if let Err(e) = metrics::start_metrics_server(
                metrics_addr,
                metrics_path,
                stats,
                max_metrics_connections,
            )
            .await
            {
                error!("Metrics server error: {e}");
            }
        });

        // Add the metrics task to the list of tasks
        tasks.push(metrics_task);
    }

    // Start the DoH servers if configured
    if !config.doh_listen_addresses.is_empty() {
        // Parse the DoH addresses
        let doh_socket_addrs = config.doh_socket_addrs()?;

        for doh_addr in doh_socket_addrs {
            // Clone the values we need for the DoH server
            let query_manager = query_manager.clone();
            let upstream_servers = config.upstream_servers.clone();
            let server_timeout = config.server_timeout;
            let dns_packet_len_max = config.dns_packet_len_max;
            let stats = global_stats.clone();
            let max_connections = config.max_doh_connections;
            let doh_rate_limiter = doh_rate_limiter.clone();
            let load_balancing_strategy = config
                .load_balancing_strategy
                .parse::<load_balancer::LoadBalancingStrategy>()
                .unwrap();

            // Create a task for the DoH server
            let doh_task = tokio::spawn(async move {
                info!("Starting DoH server on {doh_addr}");

                if let Err(e) = doh::start_doh_server(
                    doh_addr,
                    query_manager,
                    upstream_servers,
                    server_timeout,
                    dns_packet_len_max,
                    stats,
                    max_connections,
                    doh_rate_limiter,
                    load_balancing_strategy,
                )
                .await
                {
                    error!("DoH server error: {e}");
                }
            });

            // Add the DoH task to the list of tasks
            tasks.push(doh_task);
        }
    }

    // Start the control servers if configured
    if !config.control_listen_addresses.is_empty() {
        // Parse the control server addresses
        let control_socket_addrs = config.control_socket_addrs()?;

        for control_addr in control_socket_addrs {
            // Clone the values we need for the control server
            let control_path = config.control_path.clone();
            let max_connections = config.max_control_connections;
            let dns_cache = Some(dns_cache.clone());
            let stats = Some(global_stats.clone());

            // Create a task for the control server
            let control_task = tokio::spawn(async move {
                info!("Starting control server on {control_addr}, base path: {control_path}");

                if let Err(e) = control::start_control_server(
                    control_addr,
                    control_path,
                    max_connections,
                    dns_cache,
                    stats,
                )
                .await
                {
                    error!("Control server error: {e}");
                }
            });

            // Add the control task to the list of tasks
            tasks.push(control_task);
        }
    }

    // Clone the configuration values we need for the tasks
    let upstream_servers = config.upstream_servers.clone();
    let dns_packet_len_max = config.dns_packet_len_max;

    // Create a task for each UDP socket
    for (i, socket) in udp_sockets.iter().enumerate() {
        let socket = socket.clone();
        let socket_addr = socket_addrs[i];
        let udp_clients_slab = udp_clients_slab.clone();
        let upstream_servers = upstream_servers.clone();
        let query_manager = query_manager.clone();
        let udp_rate_limiter = udp_rate_limiter.clone();

        // Create a task for this UDP socket
        let task = tokio::spawn(async move {
            // Create a buffer for this task
            let mut buf = vec![0u8; dns_packet_len_max];

            // Main receive loop for this socket
            loop {
                // Log that we're waiting for a packet
                debug!("Waiting for incoming UDP packets on {socket_addr}...");

                // Wait for a packet
                match socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        debug!("Received packet of size {len} bytes from UDP client {addr}");

                        // Check rate limit for UDP client if enabled
                        if let Some(rate_limiter) = &udp_rate_limiter {
                            // Extract the client IP address
                            let client_ip = addr.ip();

                            // Check if the client is allowed to make a query
                            if !rate_limiter.is_allowed(client_ip).await {
                                warn!("Rate limit exceeded for UDP client {addr}, dropping query");
                                continue;
                            }
                        }

                        // Clone the data for the task
                        let data = buf[..len].to_vec();
                        debug!("Cloned packet data for processing");

                        // Clone the socket for the task
                        let socket_clone = socket.clone();
                        debug!("Spawning new task to handle UDP client {addr}");

                        // Create a new UDPClient
                        let client = UDPClient::new(
                            socket_clone,
                            data,
                            addr,
                            upstream_servers.clone(),
                            query_manager.clone(),
                        );

                        // Spawn a new task to handle the response
                        let udp_clients_slab_clone = udp_clients_slab.clone();
                        tokio::spawn(async move {
                            debug!("Started processing task for UDP client {addr}");

                            // Add the client to the slab
                            let client_slot = {
                                let mut slab = udp_clients_slab_clone.lock().await;

                                // If the slab is full, remove the oldest entry
                                if slab.is_full() && slab.pop_back().is_some() {
                                    debug!("UDP slab is full, removing oldest client");
                                }

                                // Add the new client to the front of the slab
                                let slot = slab
                                    .push_front(client.clone())
                                    .expect("Failed to add UDP client to slab");

                                // Increment the active UDP clients counter
                                if let Some(stats) = &client.query.stats {
                                    stats.increment_active_udp_clients().await;
                                }

                                debug!(
                                    "Added UDP client to slab with slot {}, slab size: {}",
                                    slot,
                                    slab.len()
                                );
                                slot
                            };

                            // Process the client query
                            client.process_query().await;
                            debug!("Completed processing task for UDP client {addr}");

                            // Remove the client from the slab
                            {
                                let mut slab = udp_clients_slab_clone.lock().await;

                                // Remove the client by slot
                                if let Err(e) = slab.remove(client_slot) {
                                    error!("Failed to remove UDP client from slab: {e}");
                                } else {
                                    // Decrement the active UDP clients counter
                                    if let Some(stats) = &client.query.stats {
                                        stats.decrement_active_udp_clients().await;
                                    }

                                    debug!(
                                        "Removed UDP client from slab with slot {}, slab size: {}",
                                        client_slot,
                                        slab.len()
                                    );
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to receive packet on UDP {socket_addr}: {e}");
                    }
                }
            }
        });

        tasks.push(task);
    }

    // Create a task for each TCP listener
    for (i, listener) in tcp_listeners.iter().enumerate() {
        let listener = listener.clone();
        let socket_addr = socket_addrs[i];
        let tcp_clients_slab = tcp_clients_slab.clone();
        let upstream_servers = upstream_servers.clone();
        let query_manager = query_manager.clone();
        let tcp_rate_limiter = tcp_rate_limiter.clone();

        // Create a task for this TCP listener
        let task = tokio::spawn(async move {
            // Main accept loop for this listener
            loop {
                // Log that we're waiting for a connection
                debug!("Waiting for incoming TCP connections on {socket_addr}...");

                // Wait for a connection
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("Accepted TCP connection from {addr}");

                        // Check rate limit for TCP client if enabled
                        if let Some(rate_limiter) = &tcp_rate_limiter {
                            // Extract the client IP address
                            let client_ip = addr.ip();

                            // Check if the client is allowed to make a connection
                            if !rate_limiter.is_allowed(client_ip).await {
                                warn!(
                                    "Rate limit exceeded for TCP client {addr}, dropping connection"
                                );
                                continue;
                            }
                        }

                        // Clone the necessary values for the task
                        let upstream_servers = upstream_servers.clone();
                        let query_manager = query_manager.clone();
                        let tcp_clients_slab_clone = tcp_clients_slab.clone();

                        // Spawn a new task to handle the TCP connection
                        tokio::spawn(async move {
                            debug!("Started TCP connection handler for client {addr}");

                            // Process the TCP connection
                            process_tcp_connection(
                                stream,
                                addr,
                                upstream_servers,
                                query_manager,
                                tcp_clients_slab_clone,
                                dns_packet_len_max,
                                server_timeout,
                            )
                            .await;

                            debug!("Completed TCP connection handler for client {addr}");
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept TCP connection on {socket_addr}: {e}");
                    }
                }
            }
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete (which they never will)
    for task in tasks {
        match task.await {
            Ok(_) => {} // Task completed successfully
            Err(e) => {
                error!("Task error: {e}");
                return Err(EtchDnsError::Other(format!("Task error: {e}")));
            }
        }
    }

    Ok(())
}
