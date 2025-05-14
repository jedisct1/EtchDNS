# EtchDNS

EtchDNS is a high-performance caching DNS proxy with a focus on security, reliability, and performance.

## Overview

EtchDNS acts as an intermediary between your clients and upstream DNS servers, adding key features like caching, load balancing, and security filtering. It's designed to be fast, reliable, and configurable, with support for both traditional DNS protocols and DNS-over-HTTP.

### Common Use Cases

- **Secondary DNS Server**: Quickly set up a secondary DNS server by setting `authoritative_dns = true` and pointing to your primary DNS servers as upstreams (no zone transfers required)
- **DNS Accelerator**: Place EtchDNS in front of recursive DNS servers to add caching, load balancing, and protection
- **Security Filter**: Use domain filtering to control which DNS queries are permitted
- **DoH Gateway**: Provide DNS-over-HTTP for clients while using standard DNS for upstream servers

## Features

### Core Features

- **Efficient Forwarding**: Forward DNS queries to multiple upstream DNS servers with configurable timeout and retry logic
- **Multiple Protocol Support**:
  - Standard DNS over UDP (port 53)
  - Standard DNS over TCP (port 53)
  - DNS-over-HTTP (DoH)
- **High Performance**:
  - Query aggregation to reduce duplicate upstream requests
  - Connection handling with protection against common DoS attacks
  - High-performance built-in cache using SIEVE, with serve-stale to keep responding to clients even when upstream servers are overloaded or unreachable

### Load Balancing

- **Multiple Strategies**:
  - `random`: Simple random selection of upstream servers
  - `fastest`: Select the server with the fastest recent response times
  - `p2` (Power of Two Choices): Randomly select two servers and use the faster one
- **Server Health Monitoring**: Periodically probe upstream DNS servers to track performance
- **Smart Selection**: Considers server performance when making routing decisions

### Security Features

- **Domain Filtering**:
  - Allowed zones: Restrict queries to only domains in a specified list
  - NX zones: Automatically return NXDOMAIN for domains in a blocklist
- **Rate Limiting**:
  - Configurable per protocol (UDP, TCP, DoH)
  - Limit the number of clients tracked to prevent memory exhaustion
- **Transaction ID Masking**: Helps protect against DNS poisoning attacks
- **Request Validation**: Thorough validation of DNS packets
- **Compatible with DNSSEC**

### Monitoring

- **Prometheus-Compatible Metrics**: HTTP endpoint providing operational metrics
- **Detailed Logging**: Configurable log levels for troubleshooting
- **Performance Statistics**: Track upstream server response times and success rates

### Extensibility

- **WebAssembly Hooks**: Extend EtchDNS with custom WebAssembly modules
- **Modular Design**: Clean separation of components makes code changes easier

## Installation

### From Source

1. Ensure you have Rust and Cargo installed (version 1.70.0 or newer recommended)
2. Clone this repository
3. Build the release version:

```bash
cargo build --release
```

The executable will be available at `target/release/etchdns`.

## Configuration

EtchDNS uses a TOML configuration file to control all aspects of its behavior. Here's a complete example with commentary:

```toml
# Log level (trace, debug, info, warn, error, default: warn)
log_level = "info"

# Addresses to listen on for standard DNS (UDP/TCP)
listen_addresses = ["0.0.0.0:53", "[::]:53"]

# Addresses for DNS-over-HTTP (DoH)
# If empty, DoH is disabled
doh_listen_addresses = ["127.0.0.1:443"]

# DNS packet size limits
dns_packet_len_max = 4096

# Client management limits
max_udp_clients = 1000
max_tcp_clients = 1000
max_inflight_queries = 500

# Timeout for upstream server responses (seconds)
server_timeout = 5

# Upstream DNS servers to forward queries to
upstream_servers = [
  "8.8.8.8:53",  # Google DNS
  "1.1.1.1:53",  # Cloudflare DNS
  "9.9.9.9:53"   # Quad9 DNS
]

# Load balancing strategy (random, fastest, p2)
load_balancing_strategy = "fastest"

# Monitoring setup (optional)
metrics_address = "127.0.0.1:9100"
metrics_path = "/metrics"
max_metrics_connections = 5

# Rate limiting configuration (UDP)
udp_rate_limit_window = 1      # seconds
udp_rate_limit_count = 100     # queries per window
udp_rate_limit_max_clients = 10000

# Rate limiting configuration (TCP)
tcp_rate_limit_window = 5      # seconds
tcp_rate_limit_count = 20      # queries per window
tcp_rate_limit_max_clients = 5000

# Rate limiting configuration (DoH)
doh_rate_limit_window = 10     # seconds
doh_rate_limit_count = 30      # queries per window
doh_rate_limit_max_clients = 5000

# DoH server limits
max_doh_connections = 10

# Performance monitoring
probe_interval = 60            # seconds between upstream server checks

# Caching configuration
cache_size = 10000             # number of entries
# Set to true for secondary DNS server mode (don't adjust TTLs)
authoritative_dns = false      # adjust TTLs based on cache time

# Domain filtering (optional)
allowed_zones_file = "allowed_zones.txt"
nx_zones_file = "nx_zones.txt"

# Stale cache handling
serve_stale_grace_time = 300   # seconds to serve stale entries when upstreams fail
serve_stale_ttl = 30           # TTL to use for stale entries

# Negative cache TTL
negative_cache_ttl = 60        # seconds to cache NXDOMAIN results

# WebAssembly hooks (optional)
hooks_wasm_file = "hooks.wasm"
```

### Domain Filtering

#### Allowed Zones

Create a text file with one domain per line. EtchDNS will only process queries for domains that match or are subdomains of these entries. Empty lines and lines starting with `#` are ignored.

Example `allowed_zones.txt`:
```
# Company domains
example.com
example.org

# Third-party services
github.com
google.com
```

#### NX Zones

Create a text file with domains that should return NXDOMAIN responses. Empty lines and lines starting with `#` are ignored.

Example `nx_zones.txt`:
```
# Advertising domains
ads.example.com
analytics.example.com

# Known malicious domains
malware.example.net
```

## Usage

### Running EtchDNS

```bash
./etchdns -c /path/to/config.toml
```

Command line options:
- `-c, --config <FILE>`: Path to the configuration file (required)
- `-h, --help`: Print help information
- `-V, --version`: Print version information

## Performance Tuning

For optimal performance, consider these configuration guidelines:

1. **Cache Size**: Increase `cache_size` based on available memory and expected query volume
2. **Client Limits**: Adjust `max_udp_clients` and `max_tcp_clients` based on expected concurrent clients
3. **Query Limits**: Set `max_inflight_queries` based on your server's resources
4. **Load Balancing**: Use `fastest` strategy for highest performance, or `p2` for a good balance
5. **Rate Limiting**: Set appropriate limits to prevent DoS while allowing legitimate traffic
6. **Serve Stale**: Enable `serve_stale_grace_time` to improve reliability when upstream servers fail
7. **Authoritative Mode**: Set `authoritative_dns = true` when serving as a secondary DNS server (works with any DNS provider, even those that don't support zone transfers)
8. **Metrics**: Enable metrics to monitor performance and identify bottlenecks

## Security Considerations

- Run EtchDNS with minimal privileges
- Use domain filtering to restrict which DNS queries are processed
- Set appropriate rate limits to prevent abuse
- Consider running behind a reverse proxy for DoH with TLS termination

## Advanced Usage

### WebAssembly Hooks (work in progress)

EtchDNS supports extending functionality through WebAssembly modules. Create a compatible WASM file and specify it in `hooks_wasm_file` to enable custom processing at various points in the DNS resolution pipeline.

See the `hooks-plugin` directory for details on implementing custom hook functions.

## License

This project is licensed under the MIT License.
