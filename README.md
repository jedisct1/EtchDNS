<p align="center">
  <img src="https://raw.github.com/jedisct1/etchdns/master/img/logo.png" alt="EtchDNS Logo" width="300">
</p>

<h1 align="center">EtchDNS</h1>

<p align="center">
  <strong>A caching DNS proxy with advanced security features</strong>
</p>

<p align="center">
  <strong>Visit the website for complete documentation: <a href="https://etchdns.dnscrypt.info">EtchDNS</a></strong>
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

EtchDNS is a caching DNS proxy designed for security and reliability. It acts as a protective layer between clients and upstream DNS servers, providing robust caching, intelligent load balancing, and comprehensive security features.

**Perfect for:**
- Organizations seeking to improve DNS performance and security
- Network administrators needing protection against DNS-based attacks
- Service providers looking to offload DNS traffic from primary servers
- Privacy-conscious users wanting greater control over their DNS resolution
- Developers looking for an extensible DNS platform through WebAssembly
- Secondary authoritative DNS server compatible with any provider (no zone transfer required)
- Public or local DNS cache in front of a resolver
- Intermediary between a DNSCrypt server proxy and a resolver

## Key Features

### 🚀 Performance
- **Efficient Caching**: Uses the SIEVE algorithm for optimal memory usage
- **Query Aggregation**: Eliminates duplicate in-flight queries to reduce upstream load
- **Smart Load Balancing**: Multiple strategies (fastest/p2/random) to distribute queries
- **EDNS-Client-Subnet**: Improves CDN and geolocation-based DNS responses
- **Protocol Support**: UDP/TCP (standard DNS) and basic DoH (DNS-over-HTTP)
- **Planned Protocols**: DNSCrypt, PQDNSCrypt, and Anonymized DNSCrypt for improved security and privacy

### 🔒 Security
- **Domain Filtering**: Whitelist and blacklist support with allowed/NX zones
- **IP Validation**: Block suspicious IP ranges, validate client ports, and prevent address spoofing
- **Rate Limiting**: Fine-grained control for each protocol (UDP/TCP/DoH)
- **Transaction ID Masking**: Protection against cache poisoning attacks
- **Privilege Dropping**: Run with minimal system access after initialization (user, group, and chroot)
- **Thorough Request Validation**: Comprehensive DNS packet validation

### 💪 Reliability
- **Automatic Failover**: Immediate detection of server outages for seamless query routing
- **Serve Stale**: Continue serving expired cache entries during upstream failures
- **Health Monitoring**: Regular probing of upstream servers with configurable intervals
- **Latency Guarantees**: Ensures consistent response times even during upstream slowdowns
- **Fine-grained Controls**: Separate connection limits for different protocols and in-flight queries

### 📊 Monitoring
- **Prometheus Metrics**: Comprehensive observability with Prometheus endpoint
- **Remote Control API**: HTTP interface for status monitoring and cache management
- **Detailed Logging**: Configurable query logging with customizable details
- **Log Rotation**: Size and time-based log rotation with compression support

### 🧩 Extensibility (WebAssembly)
- **Multi-language Plugin Support**: Create custom plugins in any language that compiles to WebAssembly (C/C++, Zig, AssemblyScript, etc.)
- **Custom Filter Rules**: Implement advanced filtering logic beyond static blocklists
- **Dynamic Response Modification**: Modify DNS responses based on custom business logic
- **Stateful Processing**: Maintain state across DNS queries for complex policy enforcement

## Quickstart

1. Download or clone the repository
2. Edit a copy of the [`etchdns.toml`](etchdns.toml) configuration file
3. Run EtchDNS:

```sh
etchdns -c /path/to/etchdns.toml
```

## Use Cases

### Secondary DNS Server

Reduce load on your primary DNS servers and ensure continuity of service:

```toml
# Secondary DNS server mode
authoritative_dns = true
```

EtchDNS acts as a secondary authoritative DNS server for your zones, handling client requests while reducing load on your primary servers and providing protection against common attacks. Compatible with any DNS provider without requiring zone transfers.

### Local or Public DNS Cache

Improve performance and reliability for local devices or provide a public DNS service:

```toml
# Cache mode
authoritative_dns = false
```

Configure your devices to use EtchDNS as their DNS resolver. It will cache responses, distribute queries across multiple upstream servers, and make your DNS experience more reliable and secure. Can be deployed as either a local network cache or as a public DNS service.

### DNS Firewall

Create a protective layer for your network:

```toml
# Domain blocklist configuration
nx_zones_file = "nx_zones.txt"

# IP address validation and filtering
enable_strict_ip_validation = true
block_private_ips = true
block_loopback_ips = true
blocked_ip_ranges = ["203.0.113.0/24", "198.51.100.0/24"]
min_client_port = 1024
```

Block malicious domains, ads, or unwanted content by configuring the `nx_zones.txt` file with domains that should return NXDOMAIN responses. Additionally, use IP validation to block connections from suspicious or problematic IP ranges.

EtchDNS can be used as an intermediary between a DNSCrypt server proxy (such as [encrypted-dns-server](https://github.com/DNSCrypt/encrypted-dns-server)) and your resolver to reduce load and enhance reliability.

### Custom DNS Processing with WebAssembly

Implement advanced DNS processing logic:

```toml
# WebAssembly hooks
hooks_wasm_file = "hooks.wasm"
hooks_wasm_wasi = false  # Set to true if your plugin needs WASI support
```

Use WebAssembly to implement custom filtering rules, monitoring, or modifications to DNS queries and responses.

## Installation

### From Release Binaries

Download the latest release from the [releases page](https://github.com/jedisct1/etchdns/releases).

### From Source

1. Ensure you have Rust and Cargo installed
2. Clone this repository
3. Build the release version:

```sh
cargo build --release
```

The executable will be available at `target/release/etchdns`.

#### Building with WebAssembly Hooks Support

By default, EtchDNS is built without WebAssembly hooks support to keep the binary size smaller. If you want to enable the hooks functionality, build with the `hooks` feature flag:

```sh
cargo build --release --features hooks
```
Note that enabling the hooks feature includes a WebAssembly runtime which significantly increases the binary size. Only enable this feature if you plan to use WebAssembly extensions.

## Configuration

EtchDNS uses a TOML configuration file to control all aspects of its behavior. A complete example with documentation can be found in the included [`etchdns.toml`](etchdns.toml) file.

Key configuration sections include:

- **Basic server settings**: Listen addresses, log level, packet size limits
- **Upstream DNS servers**: Servers to forward queries to
- **Load balancing**: Strategy and probe interval
- **Rate limiting**: Parameters for each protocol
- **Caching**: Cache size and TTL settings
- **Domain filtering**: Allowed and blocked zones
- **IP validation**: Client source IP filtering and security options
- **EDNS-client-subnet**: Enable/disable and prefix length configuration
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

### EDNS-Client-Subnet Support

EtchDNS supports EDNS-client-subnet (ECS) as defined in RFC 7871, which can improve CDN and geolocation-based DNS responses:

```toml
# EDNS-Client-Subnet configuration
enable_ecs = true
ecs_prefix_v4 = 24  # Send first 24 bits of IPv4 address (hide last 8 bits)
ecs_prefix_v6 = 56  # Send first 56 bits of IPv6 address (hide last 72 bits)
```

When enabled, EtchDNS will include client IP information in upstream queries, allowing DNS providers to return optimized responses based on the client's location. The prefix lengths control how much of the client's IP address is shared with upstream servers, balancing performance with privacy.

### Remote Control API

EtchDNS provides an HTTP API for remote management:

```toml
# Control API setup
control_listen_addresses = ["127.0.0.1:8080"]
control_path = "/control"
```

Available endpoints:
- `GET /control/status`: Get comprehensive server status including uptime, connection stats, and health information
- `GET /control/cache`: Get cache status information including size, hit/miss rates, and entry counts
- `DELETE /control/cache`: Clear entire cache
- `DELETE /control/cache/zone/<example.com>`: Clear all entries for a specific zone
- `DELETE /control/cache/name/<example.com>`: Clear a specific entry by name

### WebAssembly Extensions (WIP)

> **Note**: The WebAssembly extension system is currently under active development. While functional, expect API changes and additional features in future releases.

One of EtchDNS's most powerful features is its ability to be extended through WebAssembly modules. This allows you to implement custom DNS processing logic in any language that compiles to WebAssembly, including:

- C/C++
- Zig
- AssemblyScript
- Go/TinyGo
- And many others, thanks to Extism.

> **Important**: To use WebAssembly extensions, you must compile EtchDNS with the `hooks` feature flag enabled:
> ```sh
> cargo build --release --features hooks
> ```
> This includes the Extism WebAssembly runtime, which significantly increases the binary size.

#### Benefits of WebAssembly Extensions:

- **Language Flexibility**: Write extensions in your preferred programming language
- **Sandboxed Execution**: Extensions run in a secure sandbox with minimal overhead
- **Hot Reloading**: Update extensions without restarting EtchDNS
- **Stateful Processing**: Maintain state across DNS queries for complex policy enforcement
- **Extism Integration**: Built on the powerful Extism plugin system with optional WASI support

#### Current Capabilities:

The current implementation supports the following hook points:

- `hook_client_query_received`: Called when a client query is received, before checking the cache
  - Return code 0: Continue normal processing
  - Return code -1: Return minimal response with REFUSED rcode

Hooks receive query information in a structured JSON format and can process data from any language that compiles to WebAssembly.

#### Example Implementation:

EtchDNS includes an example WebAssembly plugin in the [`webassembly-plugins`](webassembly-plugins/) directory. This demonstrates how to create a simple plugin that can influence DNS query processing.

To use WebAssembly extensions, specify the path to your compiled WASM file:

```toml
# WebAssembly hooks
hooks_wasm_file = "hooks.wasm"
hooks_wasm_wasi = false  # Set to true if your plugin needs WASI support
```

#### Building Your Own Extensions:

See the [WebAssembly Extension Guide](#building-webassembly-hooks) in the Development section for details on building your own WebAssembly extensions.

## Performance Tuning

For optimal performance, consider these configuration guidelines:

1. **Cache Size**: Increase `cache_size` based on available memory
2. **Client Limits**: Adjust `max_udp_clients` and `max_tcp_clients` for your environment
3. **Load Balancing**: Use `fastest` for highest performance, `p2` for a good balance
4. **Serve Stale**: Enable `serve_stale_grace_time` for improved reliability
5. **Rate Limiting**: Set appropriate limits that prevent DoS while allowing legitimate traffic
6. **In-flight Queries**: Adjust `max_inflight_queries` for query aggregation efficiency
7. **TTL Settings**: Fine-tune various TTL settings to optimize cache performance
8. **Probe Interval**: Configure `probe_interval` to balance load balancer accuracy with network overhead

## Security

EtchDNS includes several security features to protect both clients and upstream servers:

- **Run with minimal privileges**: Use the privilege dropping feature
- **Domain filtering**: Restrict which queries are processed
- **IP validation**: Block connections from suspicious or problematic source addresses
- **Rate limiting**: Prevent abuse by limiting queries per client
- **Transaction ID masking**: Protect against cache poisoning attacks

### IP Validation

EtchDNS includes a robust IP validation system that allows you to control which client IP addresses can use your server:

```toml
# Enable strict IP validation
enable_strict_ip_validation = true

# Block private IP address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
block_private_ips = true

# Block loopback IP address ranges (127.0.0.0/8, ::1)
block_loopback_ips = true

# Minimum port to allow from clients (ports below this will be rejected)
min_client_port = 1024

# List of blocked IP ranges
blocked_ip_ranges = ["203.0.113.0/24", "198.51.100.0/24"]
```

This helps protect against IP spoofing, abuse from internal networks, and connections from known problematic IP ranges. Client port validation adds another layer of security by blocking connections from privileged ports, which are commonly used in spoofing attacks.

## Development

### Running Tests

Run the standard unit tests:

```sh
cargo test
```

### Fuzzing Tests

EtchDNS includes comprehensive fuzzing tests for the DNS parsers:

1. Install cargo-fuzz:
   ```sh
   cargo install cargo-fuzz
   ```

2. Run a specific fuzz target:
   ```sh
   cargo fuzz run validate_dns_packet
   ```

For more details on available targets, see the [fuzz/README.md](fuzz/README.md) file.

### Building WebAssembly Hooks

To build a WebAssembly extension for EtchDNS:

1. Make sure you've compiled EtchDNS with hooks support:
   ```sh
   cargo build --release --features hooks
   ```

2. Add the WebAssembly target to your Rust toolchain:
   ```sh
   rustup target add wasm32-unknown-unknown
   ```

3. Build the example Rust plugin or your own extension:
   ```sh
   cd webassembly-plugins/rust
   cargo build --target wasm32-unknown-unknown --release
   ```

4. The compiled WebAssembly module will be available at `target/wasm32-unknown-unknown/release/etchdns_hooks_rust.wasm`

5. Copy the WebAssembly module to your EtchDNS directory and update the configuration:
   ```sh
   cp target/wasm32-unknown-unknown/release/etchdns_hooks_rust.wasm /path/to/etchdns/hooks.wasm
   ```

Alternatively, you can build the Zig example plugin:

1. Navigate to the Zig plugin directory:
   ```sh
   cd webassembly-plugins/zig
   ```

2. Build the Zig plugin:
   ```sh
   zig build
   ```

3. The compiled WebAssembly module will be available in the `zig-out/bin/` directory

For other languages, consult their respective WebAssembly compilation guides. The key requirement is that the resulting WASM module exports functions that match the hook interface defined by EtchDNS.

#### WASI Support

If your WebAssembly plugin requires access to system resources (file system, environment variables, etc.), you can enable WASI support in the configuration:

```toml
# Enable WASI for WebAssembly hooks
hooks_wasm_wasi = true
```

This allows your plugin to use WASI system calls, but increases the security risk. Only enable this if your plugin specifically needs these capabilities.

> **Note**: If you try to use WebAssembly hooks with an EtchDNS binary that was compiled without the `hooks` feature, the hooks functionality will not be available and any hook-related configuration will be ignored.

## License

This project is licensed under the MIT License.

---

## Future Plans

- **Modern Protocol Support**: Future versions may include support for DNSCrypt and Anonymized DNS, potentially porting functionality from the [encrypted-dns-server](https://github.com/DNSCrypt/encrypted-dns-server) project.

> **Note**: Current DoH support is limited to traditional DoH, not Oblivious DoH (ODoH). For a mature, battle-tested DoH server implementation, consider [doh-server](https://github.com/DNSCrypt/doh-server) instead.
