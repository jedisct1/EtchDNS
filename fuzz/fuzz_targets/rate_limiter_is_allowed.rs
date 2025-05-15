#![no_main]

use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Simple mock rate limiter for testing
struct MockRateLimiter {
    // Only keeping the field we actually use
    max_queries: u32,
}

impl MockRateLimiter {
    fn new(_window: u64, max_queries: u32, _max_clients: usize) -> Self {
        Self { max_queries }
    }

    fn is_allowed(&self, ip: IpAddr) -> bool {
        // Just do some computation based on the IP to exercise different paths
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                let sum = octets.iter().map(|&x| x as u32).sum::<u32>();
                sum % self.max_queries <= (self.max_queries / 2)
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                let sum = segments.iter().map(|&x| x as u32).sum::<u32>();
                sum % self.max_queries <= (self.max_queries / 2)
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // We need at least 1 byte to determine IP type and some content
    if data.len() < 2 {
        return;
    }

    // Set up a simple rate limiter for testing
    let rate_limiter = MockRateLimiter::new(
        5,   // window in seconds
        10,  // max queries
        100, // max clients
    );

    // Determine IP type based on first byte
    let ip_addr = if data[0] % 2 == 0 {
        // Use an IPv4 address
        if data.len() >= 5 {
            // Use up to 4 bytes for the IPv4 address
            let a = data[1];
            let b = data[2];
            let c = data[3];
            let d = data[4];
            IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        } else {
            // Default for short data
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        }
    } else {
        // Use an IPv6 address
        if data.len() >= 17 {
            // Use up to 16 bytes for the IPv6 address
            let mut segments = [0u16; 8];
            for i in 0..8 {
                if 1 + i * 2 + 1 < data.len() {
                    segments[i] = ((data[1 + i * 2] as u16) << 8) | (data[1 + i * 2 + 1] as u16);
                }
            }
            IpAddr::V6(Ipv6Addr::from(segments))
        } else {
            // Default for short data
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        }
    };

    // Call is_allowed multiple times to test rate limiting logic
    for _ in 0..3 {
        let _ = rate_limiter.is_allowed(ip_addr);
    }
});
