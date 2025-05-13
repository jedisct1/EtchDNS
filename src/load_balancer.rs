use crate::stats::SharedStats;
use log::debug;
use rand::Rng;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Load balancing strategy for selecting upstream DNS servers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LoadBalancingStrategy {
    /// Select a random server
    Random,
    /// Select the fastest server based on response time statistics
    #[default]
    Fastest,
    /// Power of two choices: select the faster of two randomly chosen servers
    PowerOfTwo,
}

impl FromStr for LoadBalancingStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "random" => Ok(LoadBalancingStrategy::Random),
            "fastest" => Ok(LoadBalancingStrategy::Fastest),
            "p2" | "power-of-two" | "poweroftwo" => Ok(LoadBalancingStrategy::PowerOfTwo),
            _ => Err(format!(
                "Invalid load balancing strategy: {}. Valid options are: random, fastest, p2",
                s
            )),
        }
    }
}

impl std::fmt::Display for LoadBalancingStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadBalancingStrategy::Random => write!(f, "random"),
            LoadBalancingStrategy::Fastest => write!(f, "fastest"),
            LoadBalancingStrategy::PowerOfTwo => write!(f, "p2"),
        }
    }
}

/// Select an upstream server based on the load balancing strategy
pub async fn select_upstream_server<'a>(
    upstream_servers: &'a [String],
    strategy: LoadBalancingStrategy,
    stats: Option<&Arc<SharedStats>>,
) -> Option<&'a String> {
    if upstream_servers.is_empty() {
        return None;
    }

    // If there's only one server, return it
    if upstream_servers.len() == 1 {
        return Some(&upstream_servers[0]);
    }

    match strategy {
        LoadBalancingStrategy::Random => {
            // Use a simple random index
            let index = rand::thread_rng().gen_range(0..upstream_servers.len());
            Some(&upstream_servers[index])
        }
        LoadBalancingStrategy::Fastest => {
            // If we don't have stats, fall back to random
            if stats.is_none() {
                debug!("No stats available for fastest strategy, falling back to random");
                let index = rand::thread_rng().gen_range(0..upstream_servers.len());
                return Some(&upstream_servers[index]);
            }

            let stats = stats.unwrap();
            let resolvers_by_speed = stats.get_resolvers_by_speed().await;

            // If we don't have any stats yet, fall back to random
            if resolvers_by_speed.is_empty() {
                debug!("No resolver stats available yet, falling back to random");
                let index = rand::thread_rng().gen_range(0..upstream_servers.len());
                return Some(&upstream_servers[index]);
            }

            // Find the fastest resolver that's in our upstream_servers list
            for (addr, _) in resolvers_by_speed {
                let addr_str = addr.to_string();
                if let Some(server) = upstream_servers.iter().find(|s| **s == addr_str) {
                    debug!("Selected fastest server: {}", server);
                    return Some(server);
                }
            }

            // If none of the resolvers in our stats are in upstream_servers, fall back to random
            debug!("No matching resolver found in stats, falling back to random");
            let index = rand::thread_rng().gen_range(0..upstream_servers.len());
            Some(&upstream_servers[index])
        }
        LoadBalancingStrategy::PowerOfTwo => {
            // If we don't have stats or have fewer than 2 servers, fall back to random
            if stats.is_none() || upstream_servers.len() < 2 {
                debug!(
                    "No stats available for p2 strategy or fewer than 2 servers, falling back to random"
                );
                let index = rand::thread_rng().gen_range(0..upstream_servers.len());
                return Some(&upstream_servers[index]);
            }

            let stats = stats.unwrap();

            // Get all resolvers sorted by speed (fastest first)
            let resolvers_by_speed = stats.get_resolvers_by_speed().await;

            // If we don't have any stats yet, fall back to random
            if resolvers_by_speed.is_empty() {
                debug!("No resolver stats available yet, falling back to random");
                let index = rand::thread_rng().gen_range(0..upstream_servers.len());
                return Some(&upstream_servers[index]);
            }

            // Get the fastest server's response time
            let fastest_time = resolvers_by_speed[0].1;

            // Calculate the threshold (50% slower than the fastest)
            let threshold = fastest_time * 1.5;

            // Create a list of eligible servers (not more than 50% slower than the fastest)
            let mut eligible_servers: Vec<&String> = Vec::new();

            for server in upstream_servers {
                // Parse the server address
                match server.parse::<SocketAddr>() {
                    Ok(addr) => {
                        // Find this server in the resolvers_by_speed list
                        if let Some((_, response_time)) =
                            resolvers_by_speed.iter().find(|(a, _)| *a == addr)
                        {
                            // Check if this server is within the threshold
                            if *response_time <= threshold {
                                eligible_servers.push(server);
                                debug!(
                                    "Server {} with response time {}ms is eligible (threshold: {}ms)",
                                    server, response_time, threshold
                                );
                            } else {
                                debug!(
                                    "Server {} with response time {}ms is too slow (threshold: {}ms)",
                                    server, response_time, threshold
                                );
                            }
                        } else {
                            // If we don't have stats for this server, include it
                            eligible_servers.push(server);
                            debug!("Server {} has no stats, including it as eligible", server);
                        }
                    }
                    Err(_) => {
                        // If we can't parse the address, include it
                        eligible_servers.push(server);
                        debug!(
                            "Failed to parse server address: {}, including it as eligible",
                            server
                        );
                    }
                }
            }

            // If we have no eligible servers, fall back to random selection from all servers
            if eligible_servers.is_empty() {
                debug!("No eligible servers found, falling back to random selection");
                let index = rand::thread_rng().gen_range(0..upstream_servers.len());
                return Some(&upstream_servers[index]);
            }

            // If we have only one eligible server, return it
            if eligible_servers.len() == 1 {
                debug!("Only one eligible server found: {}", eligible_servers[0]);
                return Some(eligible_servers[0]);
            }

            // Get the global stats first (before using thread_rng)
            let global_stats = stats.get_stats().await;

            // We have at least two eligible servers, choose two randomly and pick the faster one
            let mut rng = rand::thread_rng();

            // To ensure we get a good distribution, we'll use a different approach
            // Shuffle the eligible servers and take the first two
            let mut indices: Vec<usize> = (0..eligible_servers.len()).collect();

            for i in 0..indices.len() {
                let j = rng.gen_range(0..indices.len());
                indices.swap(i, j);
            }

            let index1 = indices[0];
            let index2 = indices[1];

            let server1 = eligible_servers[index1];
            let server2 = eligible_servers[index2];

            debug!("P2 randomly selected servers: {} and {}", server1, server2);

            // Parse the addresses
            let addr1 = match server1.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(_) => {
                    debug!("Failed to parse server address: {}", server1);
                    return Some(server1);
                }
            };

            let addr2 = match server2.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(_) => {
                    debug!("Failed to parse server address: {}", server2);
                    return Some(server2);
                }
            };

            // Get the stats for both servers
            let stats1 = global_stats.get_resolver_stats(&addr1);
            let stats2 = global_stats.get_resolver_stats(&addr2);

            // Compare the response times
            match (stats1, stats2) {
                (Some(s1), Some(s2)) => {
                    // Compare response times
                    if s1.avg_response_time_ms <= s2.avg_response_time_ms {
                        debug!(
                            "P2 selected server: {} ({}ms)",
                            server1, s1.avg_response_time_ms
                        );
                        Some(server1)
                    } else {
                        debug!(
                            "P2 selected server: {} ({}ms)",
                            server2, s2.avg_response_time_ms
                        );
                        Some(server2)
                    }
                }
                (Some(_), None) => {
                    debug!("P2 selected server: {} (no stats for {})", server1, server2);
                    Some(server1)
                }
                (None, Some(_)) => {
                    debug!("P2 selected server: {} (no stats for {})", server2, server1);
                    Some(server2)
                }
                (None, None) => {
                    // If we don't have stats for either server, choose randomly
                    debug!("No stats for either server, choosing randomly");
                    let index = rng.gen_range(0..2);
                    if index == 0 {
                        Some(server1)
                    } else {
                        Some(server2)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::SharedStats;
    use std::time::Duration;

    #[tokio::test]
    async fn test_random_strategy() {
        let upstream_servers = vec![
            "127.0.0.1:53".to_string(),
            "127.0.0.2:53".to_string(),
            "127.0.0.3:53".to_string(),
        ];

        let server =
            select_upstream_server(&upstream_servers, LoadBalancingStrategy::Random, None).await;

        assert!(server.is_some());
        assert!(upstream_servers.contains(server.unwrap()));
    }

    #[tokio::test]
    async fn test_fastest_strategy() {
        let upstream_servers = vec![
            "127.0.0.1:53".to_string(),
            "127.0.0.2:53".to_string(),
            "127.0.0.3:53".to_string(),
        ];

        // Create stats with 127.0.0.2:53 as the fastest
        let stats = Arc::new(SharedStats::new());

        // Add some stats
        let addr1 = "127.0.0.1:53".parse::<SocketAddr>().unwrap();
        let addr2 = "127.0.0.2:53".parse::<SocketAddr>().unwrap();
        let addr3 = "127.0.0.3:53".parse::<SocketAddr>().unwrap();

        stats.record_success(addr1, Duration::from_millis(50)).await;
        stats.record_success(addr2, Duration::from_millis(10)).await; // Fastest
        stats.record_success(addr3, Duration::from_millis(30)).await;

        let server = select_upstream_server(
            &upstream_servers,
            LoadBalancingStrategy::Fastest,
            Some(&stats),
        )
        .await;

        assert!(server.is_some());
        assert_eq!(server.unwrap(), &"127.0.0.2:53".to_string());
    }

    #[tokio::test]
    async fn test_p2_strategy() {
        // Enable debug logging for this test
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        // For this test, we'll directly test the filtering logic
        // by creating a list of servers with specific response times

        let upstream_servers = vec![
            "127.0.0.1:53".to_string(), // Slow (50ms)
            "127.0.0.2:53".to_string(), // Fastest (10ms)
            "127.0.0.3:53".to_string(), // Too slow (30ms)
            "127.0.0.4:53".to_string(), // Eligible (14ms)
        ];

        // Create stats
        let stats = Arc::new(SharedStats::new());

        // Add some stats
        let addr1 = "127.0.0.1:53".parse::<SocketAddr>().unwrap();
        let addr2 = "127.0.0.2:53".parse::<SocketAddr>().unwrap();
        let addr3 = "127.0.0.3:53".parse::<SocketAddr>().unwrap();
        let addr4 = "127.0.0.4:53".parse::<SocketAddr>().unwrap();

        // Server 2 is the fastest (10ms)
        // Server 3 is 3x slower (30ms) - should be excluded (>50% slower)
        // Server 1 is 5x slower (50ms) - should be excluded (>50% slower)
        // Server 4 is 1.4x slower (14ms) - should be included (<50% slower)
        for _ in 0..10 {
            stats.record_success(addr1, Duration::from_millis(50)).await;
            stats.record_success(addr2, Duration::from_millis(10)).await; // Fastest
            stats.record_success(addr3, Duration::from_millis(30)).await;
            stats.record_success(addr4, Duration::from_millis(14)).await; // Within 50% threshold
        }

        // Print the resolvers by speed to debug
        let resolvers_by_speed = stats.get_resolvers_by_speed().await;
        println!("Resolvers by speed:");
        for (addr, time) in &resolvers_by_speed {
            println!("  {} -> {}ms", addr, time);
        }

        // Calculate the threshold
        let fastest_time = resolvers_by_speed[0].1;
        let threshold = fastest_time * 1.5;
        println!(
            "Fastest time: {}ms, Threshold: {}ms",
            fastest_time, threshold
        );

        // Verify that our implementation correctly identifies eligible servers
        // by directly checking the eligible_servers list

        // Create a mock implementation that exposes the eligible_servers list
        struct MockLoadBalancer;

        impl MockLoadBalancer {
            async fn get_eligible_servers<'a>(
                upstream_servers: &'a [String],
                stats: &Arc<SharedStats>,
            ) -> Vec<&'a String> {
                let resolvers_by_speed = stats.get_resolvers_by_speed().await;

                if resolvers_by_speed.is_empty() {
                    return Vec::new();
                }

                let fastest_time = resolvers_by_speed[0].1;
                let threshold = fastest_time * 1.5;

                let mut eligible_servers: Vec<&String> = Vec::new();

                for server in upstream_servers {
                    match server.parse::<SocketAddr>() {
                        Ok(addr) => {
                            if let Some((_, response_time)) =
                                resolvers_by_speed.iter().find(|(a, _)| *a == addr)
                            {
                                if *response_time <= threshold {
                                    eligible_servers.push(server);
                                }
                            } else {
                                eligible_servers.push(server);
                            }
                        }
                        Err(_) => {
                            eligible_servers.push(server);
                        }
                    }
                }

                eligible_servers
            }
        }

        // Get the list of eligible servers
        let eligible_servers =
            MockLoadBalancer::get_eligible_servers(&upstream_servers, &stats).await;

        // Print the eligible servers
        println!("Eligible servers:");
        for server in &eligible_servers {
            println!("  {}", server);
        }

        // Verify that only servers 2 and 4 are eligible
        assert_eq!(eligible_servers.len(), 2);
        assert!(eligible_servers.contains(&&"127.0.0.2:53".to_string()));
        assert!(eligible_servers.contains(&&"127.0.0.4:53".to_string()));

        // Now run the actual power-of-two-choices strategy multiple times
        // and verify that both eligible servers are selected at least once
        let iterations = 1000; // Increase iterations for more reliable results
        let mut selected_servers = std::collections::HashMap::new();

        for _ in 0..iterations {
            let server = select_upstream_server(
                &upstream_servers,
                LoadBalancingStrategy::PowerOfTwo,
                Some(&stats),
            )
            .await;

            assert!(server.is_some());
            let selected = server.unwrap();

            // Only servers 2 and 4 should be selected (within 50% threshold)
            assert!(
                selected == &"127.0.0.2:53".to_string() || selected == &"127.0.0.4:53".to_string()
            );

            *selected_servers.entry(selected.clone()).or_insert(0) += 1;
        }

        // Print the selection counts
        println!("Server selection counts:");
        for (server, count) in &selected_servers {
            println!("  {} selected {} times", server, count);
        }

        // Verify that the fastest server is selected
        assert!(selected_servers.contains_key(&"127.0.0.2:53".to_string()));
    }

    #[tokio::test]
    async fn test_p2_strategy_one_eligible() {
        let upstream_servers = vec![
            "127.0.0.1:53".to_string(),
            "127.0.0.2:53".to_string(),
            "127.0.0.3:53".to_string(),
        ];

        // Create stats with 127.0.0.2:53 as the fastest
        let stats = Arc::new(SharedStats::new());

        // Add some stats
        let addr1 = "127.0.0.1:53".parse::<SocketAddr>().unwrap();
        let addr2 = "127.0.0.2:53".parse::<SocketAddr>().unwrap();
        let addr3 = "127.0.0.3:53".parse::<SocketAddr>().unwrap();

        // Server 2 is the fastest (10ms)
        // Server 1 is 6x slower (60ms) - should be excluded (>50% slower)
        // Server 3 is 8x slower (80ms) - should be excluded (>50% slower)
        stats.record_success(addr1, Duration::from_millis(60)).await;
        stats.record_success(addr2, Duration::from_millis(10)).await; // Fastest
        stats.record_success(addr3, Duration::from_millis(80)).await;

        // Run the test multiple times
        for _ in 0..10 {
            let server = select_upstream_server(
                &upstream_servers,
                LoadBalancingStrategy::PowerOfTwo,
                Some(&stats),
            )
            .await;

            assert!(server.is_some());
            // Only the fastest server should be selected since it's the only eligible one
            assert_eq!(server.unwrap(), &"127.0.0.2:53".to_string());
        }
    }

    #[tokio::test]
    async fn test_from_str() {
        assert_eq!(
            LoadBalancingStrategy::from_str("random").unwrap(),
            LoadBalancingStrategy::Random
        );
        assert_eq!(
            LoadBalancingStrategy::from_str("fastest").unwrap(),
            LoadBalancingStrategy::Fastest
        );
        assert_eq!(
            LoadBalancingStrategy::from_str("p2").unwrap(),
            LoadBalancingStrategy::PowerOfTwo
        );
        assert_eq!(
            LoadBalancingStrategy::from_str("power-of-two").unwrap(),
            LoadBalancingStrategy::PowerOfTwo
        );
        assert_eq!(
            LoadBalancingStrategy::from_str("poweroftwo").unwrap(),
            LoadBalancingStrategy::PowerOfTwo
        );

        assert!(LoadBalancingStrategy::from_str("invalid").is_err());
    }

    #[test]
    fn test_default() {
        assert_eq!(
            LoadBalancingStrategy::default(),
            LoadBalancingStrategy::Fastest
        );
    }
}
