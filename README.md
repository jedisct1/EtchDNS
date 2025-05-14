<p align="center">
  <img src="https://raw.github.com/jedisct1/etchdns/master/img/logo.png" alt="EtchDNS Logo" width="300">
</p>

<h1 align="center">EtchDNS</h1>

<p align="center">
  <strong>A caching DNS proxy with advanced security features</strong>
</p>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#quickstart">Quickstart</a> •
  <a href="#installation">Installation</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#use-cases">Use Cases</a> •
  <a href="#advanced-features">Advanced Features</a> •
  <a href="#performance-tuning">Performance Tuning</a> •
  <a href="#security">Security</a> •
  <a href="#development">Development</a> •
  <a href="#license">License</a>
</p>

---

## What is EtchDNS?

EtchDNS is a high-performance caching DNS proxy designed for security and reliability. It acts as a protective layer between clients and upstream DNS servers, providing robust caching, intelligent load balancing, and comprehensive security features.

**Perfect for:**
- Organizations seeking to improve DNS performance and security
- Network administrators needing protection against DNS-based attacks
- Service providers looking to offload DNS traffic from primary servers
- Privacy-conscious users wanting greater control over their DNS resolution

## Key Features

### 🚀 Performance
- **Efficient Caching**: Uses the SIEVE algorithm for optimal memory usage
- **Query Aggregation**: Eliminates duplicate in-flight queries to reduce upstream load
- **Smart Load Balancing**: Multiple strategies (fastest/p2/random) to distribute queries 
- **Protocol Support**: UDP/TCP (standard DNS) and DoH (DNS-over-HTTP)

### 🔒 Security
- **Domain Filtering**: Whitelist and blacklist support with allowed/NX zones
- **Rate Limiting**: Fine-grained control for each protocol (UDP/TCP/DoH)
- **Transaction ID Masking**: Protection against cache poisoning attacks
- **Privilege Dropping**: Run with minimal system access after initialization
- **Thorough Request Validation**: Comprehensive DNS packet validation

### 💪 Reliability
- **Automatic Failover**: Immediate detection of server outages for seamless query routing
- **Serve Stale**: Continue serving expired cache entries during upstream failures
- **Health Monitoring**: Regular probing of upstream servers to ensure availability
- **Latency Guarantees**: Ensures consistent response times even during upstream slowdowns

### 📊 Monitoring
- **Prometheus Metrics**: Comprehensive observability with Prometheus endpoint
- **Remote Control API**: HTTP interface for status monitoring and cache management
- **Detailed Logging**: Configurable query logging with customizable details

### 🧩 Extensibility
- **WebAssembly Hooks**: Extend functionality through custom WASM modules
- **Modular Architecture**: Clean component separation for easy maintenance

## Quickstart

1. Download or clone the repository
2. Edit a copy of the [`config.toml`](config.toml) configuration file
3. Run EtchDNS:

```bash
etchdns -c /path/to/config.toml
```

## Use Cases

### Secondary DNS Server

Reduce load on your primary DNS servers and ensure continuity of service:

```toml
# Secondary DNS server mode
authoritative_dns = true
```

EtchDNS acts as a secondary server for your zones, handling client requests while reducing load on your primary servers and providing protection against common attacks.

### Local DNS Cache

Improve performance and reliability for local devices:

```toml
# Local cache mode
authoritative_dns = false
```

Configure your devices to use EtchDNS as their DNS resolver. It will cache responses, distribute queries across multiple upstream servers, and make your DNS experience more reliable and secure.

### DNS Firewall

Create a protective layer for your network:

```toml
# Blocklist configuration
nx_zones_file = "nx_zones.txt"
```

Block malicious domains, ads, or unwanted content by configuring the `nx_zones.txt` file with domains that should return NXDOMAIN responses.

## Installation

### From Release Binaries

Download the latest release from the [releases page](https://github.com/jedisct1/etchdns/releases).

### From Source

1. Ensure you have Rust and Cargo installed
2. Clone this repository
3. Build the release version:

```bash
cargo build --release
```

The executable will be available at `target/release/etchdns`.

## Configuration

EtchDNS uses a TOML configuration file to control all aspects of its behavior. A complete example with documentation can be found in the included [`config.toml`](config.toml) file.

Key configuration sections include:

- **Basic server settings**: Listen addresses, log level, packet size limits
- **Upstream DNS servers**: Servers to forward queries to
- **Load balancing**: Strategy and probe interval
- **Rate limiting**: Parameters for each protocol
- **Caching**: Cache size and TTL settings
- **Domain filtering**: Allowed and blocked zones
- **Security**: Privilege dropping settings

### Domain Filtering

#### Allowed Zones

Create a text file with domains that should be allowed:

```
# Company domains
example.com
example.org

# Third-party services
github.com
google.com
```

#### NX Zones (Blocklist)

Create a text file with domains that should return NXDOMAIN:

```
# Advertising domains
ads.example.com
analytics.example.com

# Known malicious domains
malware.example.net
```

## Advanced Features

### Remote Control API

EtchDNS provides an HTTP API for remote management:

```toml
# Control API setup
control_listen_addresses = ["127.0.0.1:8080"]
control_path = "/control"
```

Available endpoints:
- `GET /control/status`: Server status
- `POST /control/cache/clear`: Clear entire cache
- `POST /control/cache/clear/zone`: Clear specific zone

### WebAssembly Extensions

Extend EtchDNS with custom WebAssembly modules:

```toml
# WebAssembly hooks
hooks_wasm_file = "hooks.wasm"
```

See the [`hooks-plugin`](hooks-plugin/) directory for an example implementation.

## Performance Tuning

For optimal performance, consider these configuration guidelines:

1. **Cache Size**: Increase `cache_size` based on available memory
2. **Client Limits**: Adjust `max_udp_clients` and `max_tcp_clients` for your environment
3. **Load Balancing**: Use `fastest` for highest performance, `p2` for a good balance
4. **Serve Stale**: Enable `serve_stale_grace_time` for improved reliability
5. **Rate Limiting**: Set appropriate limits that prevent DoS while allowing legitimate traffic

## Security

EtchDNS includes several security features to protect both clients and upstream servers:

- **Run with minimal privileges**: Use the privilege dropping feature
- **Domain filtering**: Restrict which queries are processed
- **Rate limiting**: Prevent abuse by limiting queries per client
- **Transaction ID masking**: Protect against cache poisoning attacks

## Development

### Running Tests

Run the standard unit tests:

```bash
cargo test
```

### Fuzzing Tests

EtchDNS includes comprehensive fuzzing tests for the DNS parsers:

1. Install cargo-fuzz:
   ```bash
   cargo install cargo-fuzz
   ```

2. Run a specific fuzz target:
   ```bash
   cargo fuzz run validate_dns_packet
   ```

For more details on available targets, see the [fuzz/README.md](fuzz/README.md) file.

### Building WebAssembly Hooks

```bash
rustup target add wasm32-unknown-unknown
cd hooks-plugin
cargo build --target wasm32-unknown-unknown --release
```
