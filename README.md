![EtchDNS](https://raw.github.com/jedisct1/etchdns/master/img/logo.png)

# EtchDNS

A caching DNS proxy designed for security and reliability, with built-in protection mechanisms for both clients and upstream servers.

## Quickstart

1. Edit a copy of the [`config.toml`](config.toml) configuration file
2. Run `etchdns -c /path/to/config.toml`

EtchDNS can operate in two primary modes:

### EtchDNS as a secondary DNS server

For this mode, set the `authoritative_dns` property to `true`:

```toml
# Whether this server is authoritative for DNS responses
# If true, TTLs in cached responses will not be adjusted
authoritative_dns = true
```

EtchDNS will act as a "secondary DNS server" for the zones served by your primary DNS servers. The external IP address EtchDNS is listening on can be configured as a public authoritative server for your zones.

This will reduce the load on your primary servers, mitigate common attacks, and ensure continuity of service even if the primary servers have temporary outages.

### EtchDNS as a local DNS cache

For this mode, keep the default `authoritative_dns` setting as `false`:

```toml
# Whether this server is authoritative for DNS responses
# If false (default), TTLs in cached responses will be adjusted based on remaining time
authoritative_dns = false
```

Configure your local host to use EtchDNS (typically `127.0.0.1`) as a resolver. EtchDNS will cache responses, balance the load across the configured resolvers, and improve your experience by making DNS more reliable.

## Features

### Core Functionality

- **Multiple Protocol Support**: Standard DNS over UDP/TCP (port 53) and DNS-over-HTTP (DoH)
- **Efficient Caching**: Built-in cache using the SIEVE algorithm
- **Query Aggregation**: Coalesces identical in-flight queries to reduce upstream load
- **Serve Stale**: Continues serving expired cache entries during upstream failures
- **DNSSEC Compatible**: Fully supports DNSSEC for secure DNS resolution

### Load Balancing

EtchDNS offers multiple strategies for distributing queries across upstream servers:

- **Fastest**: Selects servers with the lowest response times (default)
- **Power-of-Two-Choices (p2)**: Randomly selects two servers and uses the faster one
- **Random**: Simple random selection of upstream servers

Server health is continuously monitored with periodic probes to track performance and ensure optimal routing decisions.

### Security Features

- **Domain Filtering**:
  - Allowed zones: Restrict queries to only domains in a specified list
  - NX zones: Return NXDOMAIN for domains in a blocklist
- **Rate Limiting**: Configurable per protocol (UDP, TCP, DoH) with protection against memory exhaustion
- **Request Validation**: Thorough validation of DNS packets
- **Transaction ID Masking**: Protection against DNS poisoning attacks
- **Privilege Dropping**: Ability to drop privileges after binding to ports, with configurable user, group, and chroot environment

### Reliability

- **Automatic Failover**: Quickly detects upstream server outages and routes traffic accordingly
- **Resilience Against Outages**: Serves cached responses when upstream servers are unavailable
- **Latency Guarantees**: Ensures maximum response times even during upstream slowdowns

### Monitoring and Management

- **Prometheus Metrics**: HTTP endpoint providing detailed operational metrics
- **Remote Control API**: HTTP API for remote management (cache clearing, status monitoring)
- **Configurable Logging**: Adjustable log levels from trace to error
- **Query Logging**: Optional logging of DNS queries to a file

### Extensibility

- **WebAssembly Hooks**: Extend functionality with custom WebAssembly modules
- **Modular Design**: Clean separation of components for easier maintenance and extension

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

# Control API setup (optional) - provides a simple status endpoint
control_listen_addresses = ["127.0.0.1:8080"]
control_path = "/control"
max_control_connections = 10

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

# Query logging (optional)
query_log_file = "queries.log"
query_log_include_timestamp = true
query_log_include_client_addr = true
query_log_include_query_type = true

# WebAssembly hooks (optional)
hooks_wasm_file = "hooks.wasm"

# Privilege dropping (optional, recommended for security)
user = "nobody"       # Username to drop privileges to after binding
group = "nogroup"     # Group to drop privileges to (optional)
chroot = "/var/empty" # Directory to chroot to (optional)
```

## Domain Filtering

### Allowed Zones

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

### NX Zones

Create a text file with domains that should return NXDOMAIN responses. Empty lines and lines starting with `#` are ignored.

Example `nx_zones.txt`:
```
# Advertising domains
ads.example.com
analytics.example.com

# Known malicious domains
malware.example.net
```

## Installation

### From Source

1. Ensure you have Rust and Cargo installed (version 1.70.0 or newer recommended)
2. Clone this repository
3. Build the release version:

```bash
cargo build --release
```

The executable will be available at `target/release/etchdns`.

## Usage

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
7. **Authoritative Mode**: Set `authoritative_dns = true` when serving as a secondary DNS server

## Security Considerations

- Run EtchDNS with minimal privileges
  - Use the privilege dropping feature to run as a non-root user after binding to ports
  - Configure the `user`, `group`, and `chroot` settings in the configuration file
  - Example: Start as root to bind to port 53, then drop to `nobody:nogroup` in a chroot environment
- Use domain filtering to restrict which DNS queries are processed
- Set appropriate rate limits to prevent abuse
- Consider running behind a reverse proxy for DoH with TLS termination

## Advanced Usage

### Control API

EtchDNS provides an HTTP API for remote management of the service. To enable it, configure the `control_listen_addresses` in your configuration file:

```toml
# Control API setup
control_listen_addresses = ["127.0.0.1:8080"]  # Only listen on localhost for security
control_path = "/control"                       # Base path for API endpoints
max_control_connections = 10                    # Maximum concurrent connections
```

The following endpoints are available:

- `GET /control/status`: Returns the current server status
- `POST /control/cache/clear`: Clears the entire DNS cache
- `POST /control/cache/clear/zone`: Clears DNS cache entries for a specific zone and all its subdomains

Example usage with curl:

```bash
# Check server status
curl http://127.0.0.1:8080/control/status

# Clear the entire DNS cache
curl -X POST http://127.0.0.1:8080/control/cache/clear

# Clear cache entries for example.com and all its subdomains
curl -X POST http://127.0.0.1:8080/control/cache/clear/zone \
  -H "Content-Type: application/json" \
  -d '{"zone": "example.com"}'
```

For security reasons, it's recommended to only bind the control API to localhost or a private network interface.

### WebAssembly Hooks

EtchDNS supports extending functionality through WebAssembly modules. Create a compatible WASM file and specify it in `hooks_wasm_file` to enable custom processing at various points in the DNS resolution pipeline.

Currently, the following hook points are supported:

- `hook_client_query_received`: Called when a client query is received, before checking the cache

See the `hooks-plugin` directory for details on implementing custom hook functions.

## Testing

### Unit Tests

Run the standard unit tests with:

```bash
cargo test
```

### Fuzzing Tests

EtchDNS includes fuzzing tests for the DNS parsers using `cargo-fuzz`. To run the fuzzing tests:

1. Install cargo-fuzz:
   ```bash
   cargo install cargo-fuzz
   ```

2. Run a specific fuzz target:
   ```bash
   # Run the validate_dns_packet fuzzer
   cargo fuzz run validate_dns_packet

   # Run the qname fuzzer
   cargo fuzz run qname
   ```

For more details on available fuzz targets and options, see the [fuzz/README.md](fuzz/README.md) file.

## License

This project is licensed under the MIT License.
