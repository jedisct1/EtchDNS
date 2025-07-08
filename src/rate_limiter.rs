use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Rate limiter for DNS queries
///
/// This struct tracks the number of queries from each client IP address
/// and enforces rate limits based on a configurable window and count.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// The time window for rate limiting in seconds
    window: u64,

    /// The maximum number of queries allowed per client IP in the window
    max_queries: u32,

    /// The maximum number of client IPs to track
    max_clients: usize,

    /// The internal state of the rate limiter
    state: Arc<Mutex<RateLimiterState>>,
}

/// Client activity information used for rate limiting
#[derive(Debug, Clone)]
struct ClientActivity {
    /// The query timestamps within the window
    timestamps: Vec<Instant>,

    /// Last query time (used for LRU eviction)
    last_active: Instant,

    /// Total query count (used for eviction heuristics)
    total_queries: u64,
}

/// Internal state of the rate limiter
#[derive(Debug)]
struct RateLimiterState {
    /// Map of client IP addresses to their activity information
    clients: HashMap<IpAddr, ClientActivity>,

    /// Queue for tracking client access order (for LRU eviction)
    access_order: VecDeque<IpAddr>,

    /// Last cleanup time
    last_cleanup: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    ///
    /// * `window` - The time window for rate limiting in seconds
    /// * `max_queries` - The maximum number of queries allowed per client IP in the window
    /// * `max_clients` - The maximum number of client IPs to track
    pub fn new(window: u64, max_queries: u32, max_clients: usize) -> Self {
        Self {
            window,
            max_queries,
            max_clients,
            state: Arc::new(Mutex::new(RateLimiterState {
                clients: HashMap::with_capacity(max_clients),
                access_order: VecDeque::with_capacity(max_clients),
                last_cleanup: Instant::now(),
            })),
        }
    }

    /// Check if a client is allowed to make a query
    ///
    /// # Arguments
    ///
    /// * `client_ip` - The client's IP address
    ///
    /// # Returns
    ///
    /// `true` if the client is allowed to make a query, `false` otherwise
    pub async fn is_allowed(&self, client_ip: IpAddr) -> bool {
        let mut state = self.state.lock().await;

        // Perform cleanup if it's been more than half the window since the last cleanup
        let now = Instant::now();
        if now.duration_since(state.last_cleanup) > Duration::from_secs(self.window / 2) {
            self.cleanup(&mut state, now);
        }

        // Check if the client is already being tracked
        let client_exists = state.clients.contains_key(&client_ip);

        // If the client is not already being tracked and the HashMap is full,
        // evict a client using our enhanced eviction policy
        if !client_exists && state.clients.len() >= self.max_clients && !state.clients.is_empty() {
            self.evict_client(&mut state);
        }

        // First update the access order
        if state.clients.contains_key(&client_ip) {
            // Update client's position in access order (for LRU)
            if let Some(pos) = state.access_order.iter().position(|ip| ip == &client_ip) {
                state.access_order.remove(pos);
            }
        }
        state.access_order.push_back(client_ip);

        // Get or create the client's activity record
        let activity = if let Some(activity) = state.clients.get_mut(&client_ip) {
            // Update existing client's activity record
            activity.last_active = now;
            activity.total_queries = activity.total_queries.saturating_add(1);
            activity
        } else {
            // Create new client activity record
            let activity = ClientActivity {
                timestamps: Vec::new(),
                last_active: now,
                total_queries: 1,
            };

            // Add to clients map and get a mutable reference to the stored value
            // Either we insert the new activity or we update an existing one
            let client_entry = state
                .clients
                .entry(client_ip)
                .or_insert_with(|| activity.clone());

            // If an entry already exists, update it
            if client_entry.last_active != now || client_entry.total_queries != 1 {
                client_entry.last_active = now;
                client_entry.total_queries = client_entry.total_queries.saturating_add(1);
            }

            client_entry
        };

        // Remove timestamps that are outside the window
        let window_start = now - Duration::from_secs(self.window);
        activity
            .timestamps
            .retain(|&timestamp| timestamp >= window_start);

        // Check if the client has exceeded the rate limit
        if activity.timestamps.len() >= self.max_queries as usize {
            log::warn!(
                "Rate limit exceeded for client {}: {} queries in {} seconds (limit: {})",
                client_ip,
                activity.timestamps.len(),
                self.window,
                self.max_queries
            );
            return false;
        }

        // Add the current timestamp
        activity.timestamps.push(now);

        true
    }

    /// Evict a client using a combined policy considering:
    /// 1. Least Recently Used (LRU) clients
    /// 2. Clients with fewer queries (avoid removing heavy users)
    /// 3. Clients with the oldest activity
    fn evict_client(&self, state: &mut RateLimiterState) {
        if state.access_order.is_empty() {
            return;
        }

        // First attempt: Find low-activity clients from the least recently used third
        let lru_subset_size = (state.access_order.len() / 3).max(1);
        let lru_candidates: Vec<IpAddr> = state
            .access_order
            .iter()
            .take(lru_subset_size)
            .cloned()
            .collect();

        // Find client with lowest activity from LRU subset
        if let Some(client_to_evict) = lru_candidates
            .iter()
            .min_by_key(|ip| state.clients.get(ip).map_or(u64::MAX, |a| a.total_queries))
        {
            let client_ip = *client_to_evict;
            state.clients.remove(&client_ip);

            // Remove from access order
            if let Some(pos) = state.access_order.iter().position(|ip| ip == &client_ip) {
                state.access_order.remove(pos);
            }

            log::debug!("Evicted client {client_ip} from rate limiter (low activity, LRU)");
            return;
        }

        // Fallback: If the above logic fails, simply use LRU
        if let Some(client_ip) = state.access_order.pop_front() {
            state.clients.remove(&client_ip);
            log::debug!("Evicted client {client_ip} from rate limiter (LRU fallback)");
        }
    }

    /// Clean up old entries
    ///
    /// This method removes timestamps that are outside the window and
    /// removes clients that have no timestamps.
    fn cleanup(&self, state: &mut RateLimiterState, now: Instant) {
        let window_start = now - Duration::from_secs(self.window);
        let mut clients_to_remove = Vec::new();

        // Remove timestamps that are outside the window
        for (client_ip, activity) in state.clients.iter_mut() {
            activity
                .timestamps
                .retain(|&timestamp| timestamp >= window_start);

            // Mark clients with no timestamps for removal
            if activity.timestamps.is_empty() {
                clients_to_remove.push(*client_ip);
            }
        }

        // Remove clients with no timestamps
        for client_ip in &clients_to_remove {
            state.clients.remove(client_ip);

            // Remove from access order
            if let Some(pos) = state.access_order.iter().position(|ip| ip == client_ip) {
                state.access_order.remove(pos);
            }
        }

        // Update the last cleanup time
        state.last_cleanup = now;

        log::debug!(
            "Rate limiter cleanup completed: removed {} inactive clients, tracking {} clients",
            clients_to_remove.len(),
            state.clients.len()
        );
    }

    /// Get statistics about current rate limiter state
    ///
    /// This is useful for diagnostics and monitoring
    #[allow(dead_code)]
    pub async fn get_stats(&self) -> RateLimiterStats {
        let state = self.state.lock().await;

        let now = Instant::now();
        let window_start = now - Duration::from_secs(self.window);

        let mut active_client_count = 0;
        let mut max_query_count = 0;
        let mut total_queries = 0;

        for activity in state.clients.values() {
            let recent_queries = activity
                .timestamps
                .iter()
                .filter(|&&timestamp| timestamp >= window_start)
                .count();

            if recent_queries > 0 {
                active_client_count += 1;
                max_query_count = max_query_count.max(recent_queries);
                total_queries += recent_queries;
            }
        }

        RateLimiterStats {
            total_tracked_clients: state.clients.len(),
            active_clients: active_client_count,
            max_queries_per_client: max_query_count,
            total_recent_queries: total_queries,
        }
    }
}

/// Statistics about the current state of the rate limiter
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RateLimiterStats {
    /// Total number of clients being tracked
    pub total_tracked_clients: usize,

    /// Number of clients with recent activity
    pub active_clients: usize,

    /// Maximum number of queries for any single client
    pub max_queries_per_client: usize,

    /// Total number of queries within the window
    pub total_recent_queries: usize,
}
