use std::time::{Duration, SystemTime};

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
    SyncSieveCache::<DNSKey, CachedResponse>::new(capacity).expect("Failed to create DNS cache")
}
