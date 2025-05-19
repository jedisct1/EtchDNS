use std::time::{Duration, SystemTime};

use log::{error, warn};
use sieve_cache::SyncSieveCache;

use crate::dns_key::DNSKey;

/// A cached DNS response with an expiration time
#[derive(Clone)]
pub struct CachedResponse {
    /// The raw DNS response data
    pub data: Vec<u8>,

    /// The time when this response expires
    pub expires_at: SystemTime,
}

impl CachedResponse {
    /// Create a new cached response with the given data and TTL
    pub fn new(data: Vec<u8>, ttl: Duration) -> Self {
        let expires_at = SystemTime::now() + ttl;

        Self { data, expires_at }
    }

    /// Check if the response has expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now().duration_since(self.expires_at).is_ok()
    }
}

/// A thread-safe DNS cache using SyncSieveCache
pub type SyncDnsCache = SyncSieveCache<DNSKey, CachedResponse>;

/// Create a new thread-safe DNS cache with the given capacity
pub fn create_dns_cache(capacity: usize) -> SyncDnsCache {
    // Try with requested capacity first
    if let Ok(cache) = SyncSieveCache::<DNSKey, CachedResponse>::new(capacity) {
        return cache;
    }

    // Log the failure and try with half capacity
    error!("Failed to create DNS cache with requested capacity {capacity}");
    let smaller_capacity = std::cmp::max(100, capacity / 2);
    warn!("Falling back to smaller DNS cache capacity: {smaller_capacity}");

    if let Ok(cache) = SyncSieveCache::<DNSKey, CachedResponse>::new(smaller_capacity) {
        return cache;
    }

    // Log the failure and try with minimal capacity
    error!("Failed to create DNS cache with reduced capacity {smaller_capacity}");
    let minimal_capacity = 10; // Absolute minimum size that should work
    warn!("Falling back to minimal DNS cache capacity: {minimal_capacity}");

    // Last attempt with minimal capacity
    match SyncSieveCache::<DNSKey, CachedResponse>::new(minimal_capacity) {
        Ok(cache) => cache,
        Err(e) => {
            // If this fails, create a stub implementation that doesn't actually cache
            // This allows the program to continue running, albeit with degraded functionality
            error!("Critical error: Failed to allocate even minimal DNS cache: {e}");
            warn!("Running with a non-functional cache - performance will be degraded");

            // Create a placeholder cache with capacity 0
            SyncSieveCache::<DNSKey, CachedResponse>::new(1)
                .unwrap_or_else(|_| {
                    // This should never happen with capacity 1, but just in case
                    panic!("Fatal error: Cannot allocate even a trivial cache. System is likely out of memory.")
                })
        }
    }
}
