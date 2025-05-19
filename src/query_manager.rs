use log::{error, warn};
use slabigator::Slab;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, broadcast};
use tokio::task::JoinHandle;

use crate::dns_key::DNSKey;
use crate::errors::{DnsError, DnsResult, EtchDnsResult};
use crate::load_balancer::LoadBalancingStrategy;

/// Maximum number of receivers for a single query
const MAX_RECEIVERS: usize = 100;

/// Response from a DNS query
#[derive(Clone)]
pub struct DnsResponse {
    /// The raw DNS response data
    pub data: Vec<u8>,
    /// Error message if the query failed
    pub error: Option<String>,
}

/// Manager for in-flight DNS queries
#[derive(Clone)]
pub struct QueryManager {
    /// Map of in-flight queries
    /// Key: DNSKey representing the query
    /// Value: InflightQuery containing the task and slab ID
    in_flight_queries: Arc<Mutex<HashMap<DNSKey, InflightQuery>>>,

    /// Slab for tracking the order of in-flight queries
    /// Each entry contains the DNSKey of a query
    query_slab: Arc<Mutex<Slab<DNSKey>>>,

    /// Maximum number of in-flight queries allowed
    max_inflight_queries: usize,

    /// Maximum time (in seconds) to wait for a response from an upstream server
    server_timeout: u64,

    /// Maximum DNS packet size
    dns_packet_len_max: usize,

    /// Global statistics tracker
    stats: Option<Arc<crate::stats::SharedStats>>,

    /// Load balancing strategy
    load_balancing_strategy: LoadBalancingStrategy,

    /// DNS cache
    cache: Option<crate::cache::SyncDnsCache>,

    /// Whether this server is authoritative for DNS responses
    /// If false, TTLs in cached responses will be adjusted based on remaining time
    authoritative_dns: bool,

    /// List of allowed zones
    /// If set, only queries for domains in this list will be processed
    allowed_zones: Option<crate::allowed_zones::AllowedZones>,

    /// List of nonexistent zones
    /// If set, queries for domains in this list will return NXDOMAIN directly
    nx_zones: Option<crate::nx_zones::NxZones>,

    /// Grace period in seconds to serve stale (expired) cache entries when upstream servers fail
    /// If 0, stale entries will not be served
    serve_stale_grace_time: u64,

    /// TTL in seconds to use when serving stale cache entries
    serve_stale_ttl: u32,

    /// TTL in seconds to use for negative DNS responses when no TTL is available
    negative_cache_ttl: u32,

    /// Minimum TTL in seconds for cached DNS responses
    min_cache_ttl: u32,

    /// Hooks for customizing DNS query processing
    hooks: Option<Arc<crate::hooks::SharedHooks>>,

    /// Query logger for logging DNS queries to a file
    query_logger: Option<Arc<crate::query_logger::QueryLogger>>,

    /// Whether EDNS-client-subnet is enabled
    enable_ecs: bool,

    /// IPv4 prefix length for EDNS-client-subnet
    ecs_prefix_v4: u8,

    /// IPv6 prefix length for EDNS-client-subnet
    ecs_prefix_v6: u8,
}

/// Represents a task handling a DNS query
struct QueryTask {
    /// The task handle
    task_handle: JoinHandle<DnsResponse>,
    /// The sender for broadcasting the response to all interested clients
    response_sender: broadcast::Sender<DnsResponse>,
}

/// In-flight query information
struct InflightQuery {
    /// The task handling the query
    task: QueryTask,

    /// The slab identifier for this query
    slab_id: u32,
}

impl QueryManager {
    /// Create a new QueryManager with statistics tracking
    pub fn new(
        max_inflight_queries: usize,
        server_timeout: u64,
        dns_packet_len_max: usize,
        stats: Arc<crate::stats::SharedStats>,
        load_balancing_strategy: LoadBalancingStrategy,
        authoritative_dns: bool,
        serve_stale_grace_time: u64,
        serve_stale_ttl: u32,
        negative_cache_ttl: u32,
        min_cache_ttl: u32,
        enable_ecs: bool,
        ecs_prefix_v4: u8,
        ecs_prefix_v6: u8,
    ) -> Self {
        Self {
            in_flight_queries: Arc::new(Mutex::new(HashMap::new())),
            query_slab: {
                let slab = match Slab::with_capacity(max_inflight_queries) {
                    Ok(slab) => slab,
                    Err(e) => {
                        error!("Failed to create query slab with requested capacity: {e}");
                        // Fall back to a smaller size if allocation fails
                        let smaller_capacity = std::cmp::max(100, max_inflight_queries / 2);
                        warn!("Falling back to smaller query slab capacity: {smaller_capacity}");
                        Slab::with_capacity(smaller_capacity)
                            .expect("Critical error: Failed to allocate even minimal query slab")
                    }
                };
                Arc::new(Mutex::new(slab))
            },
            max_inflight_queries,
            server_timeout,
            dns_packet_len_max,
            stats: Some(stats),
            load_balancing_strategy,
            cache: None, // Initialize cache as None, will be set later
            authoritative_dns,
            allowed_zones: None, // Initialize allowed_zones as None, will be set later if needed
            nx_zones: None,      // Initialize nx_zones as None, will be set later if needed
            serve_stale_grace_time,
            serve_stale_ttl,
            negative_cache_ttl,
            min_cache_ttl,
            hooks: None,        // Initialize hooks as None, will be set later if needed
            query_logger: None, // Initialize query_logger as None, will be set later if needed
            enable_ecs,
            ecs_prefix_v4,
            ecs_prefix_v6,
        }
    }

    /// Set the statistics tracker
    #[allow(dead_code)]
    pub fn set_stats(&mut self, stats: Arc<crate::stats::SharedStats>) {
        self.stats = Some(stats);
    }

    /// Set the DNS cache
    pub fn set_cache(&mut self, cache: crate::cache::SyncDnsCache) {
        self.cache = Some(cache);
    }

    /// Set the allowed zones
    pub fn set_allowed_zones(&mut self, allowed_zones: crate::allowed_zones::AllowedZones) {
        self.allowed_zones = Some(allowed_zones);
    }

    /// Set the nonexistent zones
    pub fn set_nx_zones(&mut self, nx_zones: crate::nx_zones::NxZones) {
        self.nx_zones = Some(nx_zones);
    }

    /// Set the hooks
    pub fn set_hooks(&mut self, hooks: Arc<crate::hooks::SharedHooks>) {
        self.hooks = Some(hooks);
    }

    /// Set the query logger
    pub fn set_query_logger(&mut self, query_logger: Arc<crate::query_logger::QueryLogger>) {
        self.query_logger = Some(query_logger);
    }

    /// Get the statistics tracker
    pub fn get_stats(&self) -> Option<Arc<crate::stats::SharedStats>> {
        self.stats.clone()
    }

    /// Get the hooks
    #[allow(dead_code)]
    pub fn get_hooks(&self) -> Option<Arc<crate::hooks::SharedHooks>> {
        self.hooks.clone()
    }

    /// Submit a query with client address and get a receiver for the response
    ///
    /// If the query is already in flight, this will add a new receiver to the existing query.
    /// If the query is not in flight, this will create a new task to handle the query.
    /// If the maximum number of in-flight queries has been reached, this will return an error.
    pub async fn submit_query_with_client(
        &self,
        key: DNSKey,
        query_data: Vec<u8>,
        resolver: impl Fn(Vec<u8>) -> futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        + Send
        + Sync
        + 'static,
        client_addr: &str,
    ) -> EtchDnsResult<broadcast::Receiver<DnsResponse>> {
        // Log the query if query logging is enabled
        if let Some(query_logger) = &self.query_logger {
            let _ = query_logger.log_query(&key, client_addr).await;
        }

        // Extract the client IP (without port) from client_addr
        // Extract the client IP by finding the part before the colon (if there is one)
        let client_ip = if let Some(ip) = client_addr.split(':').next() {
            ip
        } else {
            warn!("Unable to parse client address: {client_addr}, using 'unknown'");
            "unknown"
        };

        // Call the internal implementation with client IP
        self.submit_query_internal_with_client(key, query_data, resolver, client_ip)
            .await
    }

    /// Submit a query and get a receiver for the response
    ///
    /// If the query is already in flight, this will add a new receiver to the existing query.
    /// If the query is not in flight, this will create a new task to handle the query.
    /// If the maximum number of in-flight queries has been reached, this will return an error.
    #[allow(dead_code)]
    pub async fn submit_query(
        &self,
        key: DNSKey,
        query_data: Vec<u8>,
        resolver: impl Fn(Vec<u8>) -> futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        + Send
        + Sync
        + 'static,
    ) -> EtchDnsResult<broadcast::Receiver<DnsResponse>> {
        // Log the query if query logging is enabled
        if let Some(query_logger) = &self.query_logger {
            // Use a fake client address if not available
            let client_addr = "unknown";
            let _ = query_logger.log_query(&key, client_addr).await;
        }

        // Call the internal implementation with a default client IP
        self.submit_query_internal_with_client(key, query_data, resolver, "unknown")
            .await
    }

    /// Internal implementation of submit_query with client IP
    async fn submit_query_internal_with_client(
        &self,
        key: DNSKey,
        query_data: Vec<u8>,
        resolver: impl Fn(Vec<u8>) -> futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        + Send
        + Sync
        + 'static,
        client_ip: &str,
    ) -> EtchDnsResult<broadcast::Receiver<DnsResponse>> {
        // Record client query in stats
        if let Some(stats) = &self.stats {
            stats.record_client_query().await;
        }

        // Handle domain filtering (ANY query, nonexistent domains, allowed zones)
        if let Some(filtered_response) = self.check_domain_filters(&key, &query_data).await {
            return Ok(filtered_response);
        }

        // Process WebAssembly hooks
        if let Some(hook_response) = self.process_hooks(&key, client_ip, &query_data).await {
            return Ok(hook_response);
        }

        // Check if the response is in the cache
        if let Some(cache_response) = self.check_cache(&key, &query_data).await {
            return Ok(cache_response);
        }

        // Check in-flight queries and manage query limits
        // Use if-let instead of match to simplify the control flow
        if let Ok((mut in_flight_queries, mut query_slab)) =
            self.manage_in_flight_queries(&key).await
        {
            // Create a new task to handle the query
            let (task, receiver) = self
                .create_query_task(key.clone(), query_data, resolver)
                .await;

            // Add the key to the front of the slab to track its age
            match query_slab.push_front(key.clone()) {
                Ok(slab_id) => {
                    // Successfully added to slab, now add to the in-flight map
                    let inflight_query = InflightQuery { task, slab_id };
                    in_flight_queries.insert(key.clone(), inflight_query);

                    // No need to track in-flight queries counter, as we directly access slab length instead

                    log::debug!(
                        "Added query to slab and in-flight map, slab size: {}, map size: {}",
                        query_slab.len(),
                        in_flight_queries.len()
                    );

                    Ok(receiver)
                }
                Err(e) => {
                    log::error!("Failed to add query to slab: {e}");
                    // Since we couldn't add to the slab, we won't add to the in-flight map either
                    // This ensures they stay in sync
                    Err(DnsError::Other(format!("Failed to add query to slab: {e}")).into())
                }
            }
        } else if let Err(e) = self.manage_in_flight_queries(&key).await {
            if let Some(receiver) = e.into_receiver() {
                // Query is already in flight, return the receiver
                Ok(receiver)
            } else {
                // Some other error occurred
                Err(DnsError::Other("Failed to manage in-flight queries".to_string()).into())
            }
        } else {
            // This branch should be unreachable as we've covered all the match arms above
            Err(DnsError::Other(
                "Unreachable code in submit_query_internal_with_client".to_string(),
            )
            .into())
        }
    }

    /// Get the number of in-flight queries
    pub async fn in_flight_count(&self) -> usize {
        let query_slab = self.query_slab.lock().await;
        query_slab.len()
    }

    /// Get the server timeout in seconds
    pub fn get_server_timeout(&self) -> u64 {
        self.server_timeout
    }

    /// Get the maximum DNS packet size
    pub fn get_dns_packet_len_max(&self) -> usize {
        self.dns_packet_len_max
    }

    /// Get the load balancing strategy
    pub fn get_load_balancing_strategy(&self) -> LoadBalancingStrategy {
        self.load_balancing_strategy
    }

    /// Helper function to create a simple DNS response with flags and send it
    fn create_and_send_response_with_flags(
        query_data: &[u8],
        rcode: u8,
        authoritative_dns: bool,
        log_msg: Option<&str>,
    ) -> (
        broadcast::Sender<DnsResponse>,
        broadcast::Receiver<DnsResponse>,
    ) {
        // Create a response channel
        let (response_sender, receiver) = broadcast::channel(MAX_RECEIVERS);

        // Create the basic DNS response
        let mut dns_response =
            crate::dns_processor::create_dns_response(query_data, rcode, log_msg);

        // Set the appropriate DNS response flags
        crate::dns_processor::set_response_flags(&mut dns_response, authoritative_dns);

        // Create the response object
        let response = DnsResponse {
            data: dns_response,
            error: None,
        };

        // Send the response
        if let Err(e) = response_sender.send(response) {
            let rcode_name = match rcode {
                crate::dns_processor::DNS_RCODE_NOTIMP => "NOTIMP",
                crate::dns_processor::DNS_RCODE_NXDOMAIN => "NXDOMAIN",
                crate::dns_processor::DNS_RCODE_REFUSED => "REFUSED",
                _ => "unknown",
            };
            log::debug!("Failed to send {rcode_name} response: {e}");
        }

        (response_sender, receiver)
    }

    /// Helper function to create a response and broadcast it
    #[allow(dead_code)]
    fn create_and_broadcast_response(
        data: Vec<u8>,
        error: Option<String>,
        sender: &broadcast::Sender<DnsResponse>,
        log_prefix: &str,
    ) -> DnsResponse {
        let response = DnsResponse { data, error };

        // Send the response to all receivers
        if let Err(e) = sender.send(response.clone()) {
            // This can happen if all receivers have been dropped
            log::debug!("Failed to send {log_prefix} response: {e}");
        }

        response
    }

    /// Creates a new query task to handle a DNS query
    /// Returns a tuple (QueryTask, receiver) for the task
    async fn create_query_task(
        &self,
        key: DNSKey,
        query_data: Vec<u8>,
        resolver: impl Fn(Vec<u8>) -> futures::future::BoxFuture<'static, DnsResult<Vec<u8>>>
        + Send
        + Sync
        + 'static,
    ) -> (QueryTask, broadcast::Receiver<DnsResponse>) {
        log::debug!("Creating a new task to handle query for {}", key.name);

        // Create a broadcast channel for communicating responses
        let (response_sender, receiver) = broadcast::channel(MAX_RECEIVERS);
        let response_sender_clone = response_sender.clone();

        // Clone necessery values for the task
        let key_clone = key.clone();
        let in_flight_queries_arc = self.in_flight_queries.clone();
        let query_slab_arc = self.query_slab.clone();
        let server_timeout = self.server_timeout;
        let self_clone = self.clone();

        // Create the task
        let task_handle = tokio::spawn(async move {
            // Create a timeout for the resolver
            let timeout_duration = std::time::Duration::from_secs(server_timeout);

            // Resolve the query with a timeout
            let response =
                match tokio::time::timeout(timeout_duration, resolver(query_data.clone())).await {
                    Ok(result) => {
                        // The resolver completed within the timeout
                        match result {
                            Ok(response_data) => {
                                if crate::dns_parser::validate_dns_response(&response_data).is_err()
                                {
                                    log::debug!(
                                        "Received invalid response packet for {}",
                                        key_clone.name
                                    );
                                    // Create an error response with empty data
                                    let response = DnsResponse {
                                        data: Vec::new(),
                                        error: Some("Invalid response packet".to_string()),
                                    };

                                    // Send the response to all receivers
                                    if let Err(e) = response_sender_clone.send(response.clone()) {
                                        // This can happen if all receivers have been dropped
                                        log::debug!("Failed to send invalid response error: {e}");
                                    }

                                    // Remove the query from the in-flight map and slab
                                    Self::remove_query_from_map_and_slab(
                                        &key_clone,
                                        &in_flight_queries_arc,
                                        &query_slab_arc,
                                    )
                                    .await;

                                    // Return the response
                                    return response;
                                }
                                // Check if the response is a SERVFAIL and we should serve stale entries
                                if self_clone.serve_stale_grace_time > 0
                                    && crate::dns_parser::rcode(&response_data)
                                        == crate::dns_processor::DNS_RCODE_SERVFAIL
                                {
                                    log::debug!(
                                        "Received SERVFAIL response for {}",
                                        key_clone.name
                                    );

                                    // Check if we have a cached entry (even expired)
                                    if let Some(cache) = &self_clone.cache {
                                        if let Some(cached_response) = cache.get(&key_clone) {
                                            return Self::handle_stale_cache_entry(
                                                &key_clone,
                                                &cached_response,
                                                self_clone.serve_stale_ttl,
                                                &response_sender_clone,
                                                &in_flight_queries_arc,
                                                &query_slab_arc,
                                                cache,
                                                "SERVFAIL response",
                                            )
                                            .await;
                                        }
                                    }
                                }

                                if let Some(cache) = &self_clone.cache {
                                    self_clone.cache_dns_response(
                                        cache,
                                        &key_clone,
                                        &response_data,
                                    );
                                }

                                // Set AA and RA flags based on authoritative_dns setting
                                let mut response_data_with_flags = response_data.clone();

                                // Set the appropriate DNS response flags
                                crate::dns_processor::set_response_flags(
                                    &mut response_data_with_flags,
                                    self_clone.authoritative_dns,
                                );

                                // Create a successful response
                                let response = DnsResponse {
                                    data: response_data_with_flags,
                                    error: None,
                                };

                                // Send the response to all receivers
                                if let Err(e) = response_sender_clone.send(response.clone()) {
                                    // This can happen if all receivers have been dropped
                                    log::debug!("Failed to send successful DNS response: {e}");
                                }

                                response
                            }
                            Err(e) => {
                                // Log the error
                                log::debug!("Failed to resolve DNS query: {e}");

                                // Create an error response with empty data
                                let response = DnsResponse {
                                    data: Vec::new(),
                                    error: Some(format!("DNS query failed: {e}")),
                                };

                                // Send the response to all receivers
                                if let Err(e) = response_sender_clone.send(response.clone()) {
                                    // This can happen if all receivers have been dropped
                                    log::debug!("Failed to send error DNS response: {e}");
                                }

                                response
                            }
                        }
                    }
                    Err(_) => {
                        // The resolver timed out
                        log::debug!("DNS query timed out after {server_timeout} seconds");

                        // Check if we should serve stale entries
                        if self_clone.serve_stale_grace_time > 0 {
                            // Check if we have a stale entry in the cache
                            if let Some(cache) = &self_clone.cache {
                                if let Some(cached_response) = cache.get(&key_clone) {
                                    // Check if the cached response has expired but is within the grace period
                                    if cached_response.is_expired() {
                                        // Calculate how long ago the entry expired
                                        let expired_ago = match std::time::SystemTime::now()
                                            .duration_since(cached_response.expires_at)
                                        {
                                            Ok(duration) => duration.as_secs(),
                                            Err(_) => 0, // This shouldn't happen, but just in case
                                        };

                                        // Check if the entry is within the grace period
                                        if expired_ago <= self_clone.serve_stale_grace_time {
                                            return Self::handle_stale_cache_entry(
                                                &key_clone,
                                                &cached_response,
                                                self_clone.serve_stale_ttl,
                                                &response_sender_clone,
                                                &in_flight_queries_arc,
                                                &query_slab_arc,
                                                cache,
                                                &format!(
                                                    "timeout (expired {expired_ago} seconds ago)"
                                                ),
                                            )
                                            .await;
                                        }
                                    }
                                }
                            }
                        }

                        // Create a timeout error response
                        let response = DnsResponse {
                            data: Vec::new(),
                            error: Some(format!(
                                "DNS query timed out after {server_timeout} seconds"
                            )),
                        };

                        // Send the response to all receivers
                        if let Err(e) = response_sender_clone.send(response.clone()) {
                            // This can happen if all receivers have been dropped
                            log::debug!("Failed to send timeout DNS response: {e}");
                        }

                        response
                    }
                };

            // Response has already been broadcast to all receivers

            // Remove the query from the in-flight map and slab
            // We need to acquire both locks to ensure atomicity
            let mut in_flight_queries = in_flight_queries_arc.lock().await;
            let mut query_slab = query_slab_arc.lock().await;

            // Check if the key exists in the map
            if let Some(inflight_query) = in_flight_queries.remove(&key_clone) {
                // Remove from the slab using the stored slab ID
                match query_slab.remove(inflight_query.slab_id) {
                    Ok(_) => {
                        // No need to track in-flight queries counter, as we directly access slab length instead

                        log::debug!(
                            "Successfully removed query from both map and slab, slab size: {}, map size: {}",
                            query_slab.len(),
                            in_flight_queries.len()
                        );
                    }
                    Err(e) => {
                        log::error!("Failed to remove query from slab: {e}");
                        log::warn!("Map and slab may be out of sync due to slab removal error");
                    }
                }
            } else {
                // Not found in the map
                log::warn!("Attempted to remove non-existent query from map");
            }

            // Return the response
            response
        });

        // Create and return the QueryTask
        let task = QueryTask {
            task_handle,
            response_sender,
        };

        (task, receiver)
    }

    /// Helper function to handle stale cache entries
    async fn handle_stale_cache_entry(
        key: &DNSKey,
        cached_response: &crate::cache::CachedResponse,
        serve_stale_ttl: u32,
        response_sender: &broadcast::Sender<DnsResponse>,
        in_flight_queries_arc: &Arc<Mutex<HashMap<DNSKey, InflightQuery>>>,
        query_slab_arc: &Arc<Mutex<Slab<DNSKey>>>,
        cache: &crate::cache::SyncDnsCache,
        reason: &str,
    ) -> DnsResponse {
        log::debug!(
            "Serving stale entry for {} after {} (expired)",
            key.name,
            reason
        );

        // Create a response from the stale cached data
        let mut response_data = cached_response.data.clone();

        // Set the TTL to the configured stale TTL
        if let Err(e) = crate::dns_parser::change_ttl(&mut response_data, serve_stale_ttl) {
            log::debug!("Failed to update TTL in stale response: {e}");
        } else {
            log::debug!("Set TTL in stale response to {serve_stale_ttl} seconds");
        }

        // Get the authoritative_dns setting from the QueryManager
        // For stale entries, we're always acting as a cache, so authoritative_dns should be false
        let authoritative_dns = false;

        // Set the appropriate DNS response flags
        crate::dns_processor::set_response_flags(&mut response_data, authoritative_dns);

        // Create the stale response
        let response = DnsResponse {
            data: response_data,
            error: None,
        };

        // Update the cache with the new TTL
        let ttl_duration = std::time::Duration::from_secs(serve_stale_ttl as u64);
        let updated_cached_response =
            crate::cache::CachedResponse::new(response.data.clone(), ttl_duration);
        cache.insert(key.clone(), updated_cached_response);

        // Send the response to all receivers
        if let Err(e) = response_sender.send(response.clone()) {
            // This can happen if all receivers have been dropped
            log::debug!("Failed to send stale DNS response after {reason}: {e}");
        }

        // Remove the query from the in-flight map and slab
        Self::remove_query_from_map_and_slab(key, in_flight_queries_arc, query_slab_arc).await;

        // Return the response
        response
    }

    /// Manages in-flight queries and handles query limits
    /// Returns Ok(locks) if a new query should be created, or Err with a receiver if the query is already in flight
    async fn manage_in_flight_queries(
        &self,
        key: &DNSKey,
    ) -> Result<
        (
            tokio::sync::MutexGuard<'_, HashMap<DNSKey, InflightQuery>>,
            tokio::sync::MutexGuard<'_, Slab<DNSKey>>,
        ),
        DnsError,
    > {
        let mut in_flight_queries = self.in_flight_queries.lock().await;

        // Check if the query is already in flight
        if let Some(inflight_query) = in_flight_queries.get(key) {
            // Query is already in flight, subscribe to the response
            let receiver = inflight_query.task.response_sender.subscribe();
            return Err(DnsError::AlreadyInFlight(receiver));
        }

        // Check if we've reached the maximum number of in-flight queries
        let mut query_slab = self.query_slab.lock().await;

        if in_flight_queries.len() >= self.max_inflight_queries {
            log::warn!(
                "Maximum number of in-flight queries ({}) reached, aborting oldest query",
                self.max_inflight_queries
            );

            // Find the oldest query to abort (the one at the back of the slab)
            match query_slab.pop_back() {
                Some(oldest_key) => {
                    // Get the task from the map and remove it
                    match in_flight_queries.remove(&oldest_key) {
                        Some(inflight_query) => {
                            // Abort the task
                            inflight_query.task.task_handle.abort();

                            // Create an empty response with error message
                            let error_msg = "Query aborted due to maximum in-flight queries limit";
                            let empty_response = DnsResponse {
                                data: Vec::new(),
                                error: Some(error_msg.to_string()),
                            };

                            // Ignore errors when sending - this can happen if all receivers have been dropped
                            let _ = inflight_query.task.response_sender.send(empty_response);

                            log::info!("Aborted and removed oldest in-flight query");
                        }
                        None => {
                            // This should not happen if the map and slab are in sync
                            log::error!(
                                "Map and slab out of sync: key found in slab but not in map"
                            );

                            // Try to find any entry in the map to remove
                            self.remove_random_query(&mut in_flight_queries).await;
                        }
                    }
                }
                None => {
                    // This should not happen if the map and slab are in sync
                    log::error!("Map and slab out of sync: map has entries but slab is empty");

                    // Try to find any entry in the map to remove
                    self.remove_random_query(&mut in_flight_queries).await;
                }
            }
        }

        Ok((in_flight_queries, query_slab))
    }

    /// Removes a random query from the in-flight queries map when map/slab are out of sync
    async fn remove_random_query(
        &self,
        in_flight_queries: &mut tokio::sync::MutexGuard<'_, HashMap<DNSKey, InflightQuery>>,
    ) {
        // First, get a key to remove
        let random_key_opt = in_flight_queries.keys().next().cloned();

        if let Some(random_key) = random_key_opt {
            // Get and remove the task
            if let Some(inflight_query) = in_flight_queries.remove(&random_key) {
                // Abort the task
                inflight_query.task.task_handle.abort();

                // Create an empty response with error message
                let error_msg = "Query aborted due to maximum in-flight queries limit";
                let empty_response = DnsResponse {
                    data: Vec::new(),
                    error: Some(error_msg.to_string()),
                };

                let _ = inflight_query.task.response_sender.send(empty_response);

                log::warn!("Aborted and removed a random query due to map/slab inconsistency");
            }
        }
    }

    /// Checks if a response for this query is in the cache
    /// Returns Some(receiver) if a valid cache entry is found, None otherwise
    async fn check_cache(
        &self,
        key: &DNSKey,
        _query_data: &[u8],
    ) -> Option<broadcast::Receiver<DnsResponse>> {
        // Check if cache is enabled
        if let Some(cache) = &self.cache {
            if let Some(cached_response) = cache.get(key) {
                // Check if the cached response has expired
                if !cached_response.is_expired() {
                    log::debug!("Cache hit for query: {}", key.name);

                    // Record cache hit in stats
                    if let Some(stats) = &self.stats {
                        stats.record_cache_hit().await;
                    }

                    // Create a response channel
                    let (response_sender, receiver) = broadcast::channel(MAX_RECEIVERS);

                    // Create a successful response from the cached data
                    let mut response_data = cached_response.data.clone();

                    // If not authoritative, adjust the TTL based on remaining time
                    if !self.authoritative_dns {
                        // Calculate remaining TTL in seconds
                        let remaining_ttl = match cached_response
                            .expires_at
                            .duration_since(std::time::SystemTime::now())
                        {
                            Ok(remaining) => remaining.as_secs() as u32,
                            Err(_) => 0, // If expiration is in the past, use 0
                        };

                        // Update the TTL in the response
                        if let Err(e) =
                            crate::dns_parser::change_ttl(&mut response_data, remaining_ttl)
                        {
                            log::debug!("Failed to update TTL in cached response: {e}");
                        } else {
                            log::debug!(
                                "Adjusted TTL in cached response to {remaining_ttl} seconds"
                            );
                        }
                    }

                    // Set the appropriate DNS response flags
                    crate::dns_processor::set_response_flags(
                        &mut response_data,
                        self.authoritative_dns,
                    );

                    let response = DnsResponse {
                        data: response_data,
                        error: None,
                    };

                    // Send the cached response
                    if let Err(e) = response_sender.send(response) {
                        log::debug!("Failed to send cached DNS response: {e}");
                    }

                    return Some(receiver);
                } else {
                    log::debug!(
                        "Cache hit for query: {}, but response has expired",
                        key.name
                    );
                    // Record cache miss in stats (expired entries count as misses)
                    if let Some(stats) = &self.stats {
                        stats.record_cache_miss().await;
                    }
                }
            } else {
                log::debug!("Cache miss for query: {}", key.name);
                // Record cache miss in stats
                if let Some(stats) = &self.stats {
                    stats.record_cache_miss().await;
                }
            }
        }

        // No valid cache entry found, continue normal processing
        None
    }

    /// Helper function to cache a DNS response
    fn cache_dns_response(
        &self,
        cache: &crate::cache::SyncDnsCache,
        key: &DNSKey,
        response_data: &[u8],
    ) {
        // Extract the minimum TTL from the response
        let extracted_ttl = match crate::dns_parser::extract_min_ttl(response_data) {
            Ok(Some(ttl)) => ttl,
            _ => self.negative_cache_ttl, // Use configured TTL for negative responses
        };

        // Apply the minimum cache TTL if needed
        // This applies in both authoritative and non-authoritative modes
        // The difference is that in authoritative mode, we return the original TTL to clients
        // while in non-authoritative mode, we adjust the TTL based on remaining time
        let ttl = std::cmp::max(extracted_ttl, self.min_cache_ttl);

        // Create a cached response with the TTL
        // ttl is already in seconds, so we convert it to Duration
        let ttl_duration = std::time::Duration::from_secs(ttl as u64);
        let cached_response =
            crate::cache::CachedResponse::new(response_data.to_vec(), ttl_duration);

        // Store the response in the cache
        cache.insert(key.clone(), cached_response);

        if ttl > extracted_ttl {
            log::debug!(
                "Stored DNS response in cache with minimum TTL: {ttl} seconds (original TTL was {extracted_ttl} seconds)"
            );
        } else {
            log::debug!("Stored DNS response in cache with TTL: {ttl} seconds");
        }
    }

    /// Processes WebAssembly hooks for a query
    /// Returns Some(receiver) if a hook interrupts normal processing, None if processing should continue
    async fn process_hooks(
        &self,
        key: &DNSKey,
        client_ip: &str,
        query_data: &[u8],
    ) -> Option<broadcast::Receiver<DnsResponse>> {
        // Check if hooks are configured
        if let Some(hooks) = &self.hooks {
            let hook_result = hooks.hook_client_query_received(
                &key.name, key.qtype, key.qclass, client_ip, query_data,
            );

            // Handle different hook return codes
            match hook_result {
                0 => {
                    // Continue normal processing
                    log::debug!("Hook returned 0, continuing normal processing");
                    None
                }
                -1 => {
                    // Return a minimal response with REFUSED rcode
                    log::debug!("Hook returned -1, returning REFUSED response");

                    let log_msg = format!("Query refused by hook: {}", key.name);
                    let (_, receiver) = Self::create_and_send_response_with_flags(
                        query_data,
                        crate::dns_processor::DNS_RCODE_REFUSED,
                        self.authoritative_dns,
                        Some(&log_msg),
                    );

                    Some(receiver)
                }
                _ => {
                    // For other values, return an empty response with an error message
                    log::debug!(
                        "Hook returned unexpected value: {hook_result}, returning error response"
                    );

                    let (response_sender, receiver) = broadcast::channel(MAX_RECEIVERS);
                    let response = DnsResponse {
                        data: Vec::new(),
                        error: Some(format!(
                            "Query processing interrupted by hook (code: {hook_result})"
                        )),
                    };

                    if let Err(e) = response_sender.send(response) {
                        log::debug!("Failed to send hook-interrupted response: {e}");
                    }

                    Some(receiver)
                }
            }
        } else {
            // No hooks configured, continue normal processing
            None
        }
    }

    /// Checks if a query should be filtered based on domain restrictions
    /// Returns Some(receiver) if the query should be filtered, None if processing should continue
    async fn check_domain_filters(
        &self,
        key: &DNSKey,
        query_data: &[u8],
    ) -> Option<broadcast::Receiver<DnsResponse>> {
        // Check if the query is of type ANY (255)
        if key.qtype == crate::dns_parser::DNS_TYPE_ANY {
            let log_msg = format!(
                "Received query of type ANY for {}, returning NOTIMP",
                key.name
            );

            let (_, receiver) = Self::create_and_send_response_with_flags(
                query_data,
                crate::dns_processor::DNS_RCODE_NOTIMP,
                self.authoritative_dns,
                Some(&log_msg),
            );

            return Some(receiver);
        }

        // Check if the query is for a nonexistent domain
        if let Some(nx_zones) = &self.nx_zones {
            if nx_zones.is_nonexistent(&key.name) {
                log::debug!("Query for nonexistent domain: {}", key.name);

                let log_msg = format!("Query for nonexistent domain: {}", key.name);
                let (_, receiver) = Self::create_and_send_response_with_flags(
                    query_data,
                    crate::dns_processor::DNS_RCODE_NXDOMAIN,
                    self.authoritative_dns,
                    Some(&log_msg),
                );

                return Some(receiver);
            }
        }

        // Check if the query is allowed based on the domain name
        if let Some(allowed_zones) = &self.allowed_zones {
            if !allowed_zones.is_allowed(&key.name) {
                log::warn!("Query rejected: {} is not in allowed zones", key.name);

                let log_msg = format!("Query rejected: {} is not in allowed zones", key.name);
                let (_, receiver) = Self::create_and_send_response_with_flags(
                    query_data,
                    crate::dns_processor::DNS_RCODE_REFUSED,
                    self.authoritative_dns,
                    Some(&log_msg),
                );

                return Some(receiver);
            }
        }

        // Query passed all filters, continue processing
        None
    }

    /// Helper function to remove a query from the in-flight map and slab
    async fn remove_query_from_map_and_slab(
        key: &DNSKey,
        in_flight_queries_arc: &Arc<Mutex<HashMap<DNSKey, InflightQuery>>>,
        query_slab_arc: &Arc<Mutex<Slab<DNSKey>>>,
    ) {
        // We need to acquire both locks to ensure atomicity
        let mut in_flight_queries = in_flight_queries_arc.lock().await;
        let mut query_slab = query_slab_arc.lock().await;

        // Check if the key exists in the map
        if let Some(inflight_query) = in_flight_queries.remove(key) {
            // Remove from the slab using the stored slab ID
            match query_slab.remove(inflight_query.slab_id) {
                Ok(_) => {
                    log::debug!(
                        "Successfully removed query from both map and slab, slab size: {}, map size: {}",
                        query_slab.len(),
                        in_flight_queries.len()
                    );
                }
                Err(e) => {
                    log::error!("Failed to remove query from slab: {e}");
                    log::warn!("Map and slab may be out of sync due to slab removal error");
                }
            }
        } else {
            // Not found in the map
            log::warn!("Attempted to remove non-existent query from map");
        }
    }

    /// Get whether EDNS-client-subnet is enabled
    pub fn get_enable_ecs(&self) -> bool {
        self.enable_ecs
    }

    /// Get the IPv4 prefix length for EDNS-client-subnet
    pub fn get_ecs_prefix_v4(&self) -> u8 {
        self.ecs_prefix_v4
    }

    /// Get the IPv6 prefix length for EDNS-client-subnet
    pub fn get_ecs_prefix_v6(&self) -> u8 {
        self.ecs_prefix_v6
    }
}
