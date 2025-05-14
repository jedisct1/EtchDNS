use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;

/// Statistics for a single resolver
#[derive(Debug, Clone)]
pub struct ResolverStats {
    /// Moving average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Number of successful queries
    pub success_count: u64,
    /// Number of failed queries
    pub failure_count: u64,
    /// Number of timed out queries
    pub timeout_count: u64,
    /// Last time this resolver was used
    pub last_used: SystemTime,
    /// Weight factor for the moving average (between 0 and 1)
    /// Lower values give more weight to historical data
    weight_factor: f64,
}

impl ResolverStats {
    /// Create a new ResolverStats with default values
    pub fn new() -> Self {
        Self {
            avg_response_time_ms: 0.0,
            success_count: 0,
            failure_count: 0,
            timeout_count: 0,
            last_used: SystemTime::now(),
            weight_factor: 0.2, // 20% weight to new values
        }
    }

    /// Update the moving average response time
    pub fn update_response_time(&mut self, response_time: Duration) {
        let response_time_ms = response_time.as_millis() as f64;

        if self.avg_response_time_ms == 0.0 {
            // First measurement
            self.avg_response_time_ms = response_time_ms;
        } else {
            // Update moving average
            self.avg_response_time_ms = (1.0 - self.weight_factor) * self.avg_response_time_ms
                + self.weight_factor * response_time_ms;
        }
    }

    /// Record a successful query
    pub fn record_success(&mut self, response_time: Duration) {
        self.success_count += 1;
        self.last_used = SystemTime::now();
        self.update_response_time(response_time);
    }

    /// Record a failed query
    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_used = SystemTime::now();
    }

    /// Record a timed out query
    pub fn record_timeout(&mut self) {
        self.timeout_count += 1;
        self.last_used = SystemTime::now();
    }
}

impl Default for ResolverStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Global statistics for the DNS server
#[derive(Debug, Clone)]
pub struct GlobalStats {
    /// Total number of queries processed
    pub total_queries: u64,
    /// Total number of successful queries
    pub total_successful: u64,
    /// Total number of failed queries
    pub total_failed: u64,
    /// Total number of timed out queries
    pub total_timeouts: u64,
    /// Total number of client queries received
    pub client_queries: u64,
    /// Total number of cache hits
    pub cache_hits: u64,
    /// Total number of cache misses
    pub cache_misses: u64,
    /// Current number of active UDP clients
    pub active_udp_clients: u64,
    /// Current number of active TCP clients
    pub active_tcp_clients: u64,
    /// Current number of active in-flight queries
    pub active_inflight_queries: u64,
    /// Map of resolver addresses to their stats
    pub resolver_stats: HashMap<SocketAddr, ResolverStats>,
}

impl GlobalStats {
    /// Create a new GlobalStats with default values
    pub fn new() -> Self {
        Self {
            total_queries: 0,
            total_successful: 0,
            total_failed: 0,
            total_timeouts: 0,
            client_queries: 0,
            cache_hits: 0,
            cache_misses: 0,
            active_udp_clients: 0,
            active_tcp_clients: 0,
            active_inflight_queries: 0,
            resolver_stats: HashMap::new(),
        }
    }

    /// Record a successful query for a resolver
    pub fn record_success(&mut self, resolver: SocketAddr, response_time: Duration) {
        self.total_queries += 1;
        self.total_successful += 1;

        let stats = self.resolver_stats.entry(resolver).or_default();
        stats.record_success(response_time);
    }

    /// Record a failed query for a resolver
    pub fn record_failure(&mut self, resolver: SocketAddr) {
        self.total_queries += 1;
        self.total_failed += 1;

        let stats = self.resolver_stats.entry(resolver).or_default();
        stats.record_failure();
    }

    /// Record a timed out query for a resolver
    pub fn record_timeout(&mut self, resolver: SocketAddr) {
        self.total_queries += 1;
        self.total_timeouts += 1;

        let stats = self.resolver_stats.entry(resolver).or_default();
        stats.record_timeout();
    }

    /// Get statistics for a specific resolver
    pub fn get_resolver_stats(&self, resolver: &SocketAddr) -> Option<&ResolverStats> {
        self.resolver_stats.get(resolver)
    }

    /// Record a client query
    pub fn record_client_query(&mut self) {
        self.client_queries += 1;
    }

    /// Record a cache hit
    pub fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }

    /// Record a cache miss
    pub fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }

    /// Increment the active UDP clients counter
    pub fn increment_active_udp_clients(&mut self) {
        self.active_udp_clients += 1;
    }

    /// Decrement the active UDP clients counter
    pub fn decrement_active_udp_clients(&mut self) {
        if self.active_udp_clients > 0 {
            self.active_udp_clients -= 1;
        }
    }

    /// Increment the active TCP clients counter
    pub fn increment_active_tcp_clients(&mut self) {
        self.active_tcp_clients += 1;
    }

    /// Decrement the active TCP clients counter
    pub fn decrement_active_tcp_clients(&mut self) {
        if self.active_tcp_clients > 0 {
            self.active_tcp_clients -= 1;
        }
    }

    /// Increment the active in-flight queries counter
    pub fn increment_active_inflight_queries(&mut self) {
        self.active_inflight_queries += 1;
    }

    /// Decrement the active in-flight queries counter
    pub fn decrement_active_inflight_queries(&mut self) {
        if self.active_inflight_queries > 0 {
            self.active_inflight_queries -= 1;
        }
    }

    /// Get a list of resolvers sorted by response time (fastest first)
    pub fn get_resolvers_by_speed(&self) -> Vec<(SocketAddr, f64)> {
        let mut resolvers: Vec<(SocketAddr, f64)> = self
            .resolver_stats
            .iter()
            .map(|(addr, stats)| (*addr, stats.avg_response_time_ms))
            .collect();

        // Sort by response time (ascending)
        resolvers.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        resolvers
    }
}

impl Default for GlobalStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe wrapper for GlobalStats
#[derive(Debug, Clone)]
pub struct SharedStats {
    inner: Arc<Mutex<GlobalStats>>,
}

impl SharedStats {
    /// Create a new SharedStats
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(GlobalStats::new())),
        }
    }

    /// Record a successful query
    pub async fn record_success(&self, resolver: SocketAddr, response_time: Duration) {
        let mut stats = self.inner.lock().await;
        stats.record_success(resolver, response_time);
    }

    /// Record a failed query
    pub async fn record_failure(&self, resolver: SocketAddr) {
        let mut stats = self.inner.lock().await;
        stats.record_failure(resolver);
    }

    /// Record a timed out query
    pub async fn record_timeout(&self, resolver: SocketAddr) {
        let mut stats = self.inner.lock().await;
        stats.record_timeout(resolver);
    }

    /// Get a snapshot of the global stats
    pub async fn get_stats(&self) -> GlobalStats {
        let stats = self.inner.lock().await;
        stats.clone()
    }

    /// Record a client query
    pub async fn record_client_query(&self) {
        let mut stats = self.inner.lock().await;
        stats.record_client_query();
    }

    /// Record a cache hit
    pub async fn record_cache_hit(&self) {
        let mut stats = self.inner.lock().await;
        stats.record_cache_hit();
    }

    /// Record a cache miss
    pub async fn record_cache_miss(&self) {
        let mut stats = self.inner.lock().await;
        stats.record_cache_miss();
    }

    /// Increment the active UDP clients counter
    pub async fn increment_active_udp_clients(&self) {
        let mut stats = self.inner.lock().await;
        stats.increment_active_udp_clients();
    }

    /// Decrement the active UDP clients counter
    pub async fn decrement_active_udp_clients(&self) {
        let mut stats = self.inner.lock().await;
        stats.decrement_active_udp_clients();
    }

    /// Increment the active TCP clients counter
    pub async fn increment_active_tcp_clients(&self) {
        let mut stats = self.inner.lock().await;
        stats.increment_active_tcp_clients();
    }

    /// Decrement the active TCP clients counter
    pub async fn decrement_active_tcp_clients(&self) {
        let mut stats = self.inner.lock().await;
        stats.decrement_active_tcp_clients();
    }

    /// Increment the active in-flight queries counter
    pub async fn increment_active_inflight_queries(&self) {
        let mut stats = self.inner.lock().await;
        stats.increment_active_inflight_queries();
    }

    /// Decrement the active in-flight queries counter
    pub async fn decrement_active_inflight_queries(&self) {
        let mut stats = self.inner.lock().await;
        stats.decrement_active_inflight_queries();
    }

    /// Get a list of resolvers sorted by response time (fastest first)
    pub async fn get_resolvers_by_speed(&self) -> Vec<(SocketAddr, f64)> {
        let stats = self.inner.lock().await;
        stats.get_resolvers_by_speed()
    }
}

impl Default for SharedStats {
    fn default() -> Self {
        Self::new()
    }
}
