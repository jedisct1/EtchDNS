use std::collections::HashMap;
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

/// Internal state of the rate limiter
#[derive(Debug)]
struct RateLimiterState {
    /// Map of client IP addresses to their query counts and timestamps
    clients: HashMap<IpAddr, Vec<Instant>>,

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
                clients: HashMap::new(),
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
        // remove the first entry that is different from the one we want to insert
        if !client_exists && state.clients.len() >= self.max_clients && !state.clients.is_empty() {
            self.remove_first_entry(&mut state, client_ip);
        }

        // Get the client's query timestamps
        let timestamps = state.clients.entry(client_ip).or_insert_with(Vec::new);

        // Remove timestamps that are outside the window
        let window_start = now - Duration::from_secs(self.window);
        timestamps.retain(|&timestamp| timestamp >= window_start);

        // Check if the client has exceeded the rate limit
        if timestamps.len() >= self.max_queries as usize {
            log::warn!(
                "Rate limit exceeded for client {}: {} queries in {} seconds (limit: {})",
                client_ip,
                timestamps.len(),
                self.window,
                self.max_queries
            );
            return false;
        }

        // Add the current timestamp
        timestamps.push(now);

        true
    }

    /// Remove the first entry from the HashMap that is different from the specified client IP
    fn remove_first_entry(&self, state: &mut RateLimiterState, client_ip: IpAddr) {
        // Find the first key that is different from the one we want to insert
        if let Some(first_key) = state.clients.keys().find(|&&k| k != client_ip).cloned() {
            // Remove the first entry
            state.clients.remove(&first_key);
            log::debug!(
                "Removed client {} from rate limiter due to capacity limit",
                first_key
            );
        }
    }

    /// Clean up old entries
    ///
    /// This method removes timestamps that are outside the window and
    /// removes clients that have no timestamps.
    fn cleanup(&self, state: &mut RateLimiterState, now: Instant) {
        let window_start = now - Duration::from_secs(self.window);

        // Remove timestamps that are outside the window and clients with no timestamps
        state.clients.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| timestamp >= window_start);
            !timestamps.is_empty()
        });

        // Update the last cleanup time
        state.last_cleanup = now;

        log::debug!(
            "Rate limiter cleanup completed, tracking {} clients",
            state.clients.len()
        );
    }
}
