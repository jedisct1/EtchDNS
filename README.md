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
- Developers looking for an extensible DNS platform through WebAssembly
- Secondary authoritative DNS server compatible with any provider (no zone transfer required)
- Public or local DNS cache in front of a resolver
- Intermediary between a [DNSCrypt server proxy](https://github.com/DNSCrypt/encrypted-dns-server) and a resolver

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

### 🧩 Extensibility (WebAssembly)
- **Multi-language Plugin Support**: Create custom plugins in any language that compiles to WebAssembly (C/C++, Zig, AssemblyScript, etc.)
- **Custom Filter Rules**: Implement advanced filtering logic beyond static blocklists
- **Dynamic Response Modification**: Modify DNS responses based on custom business logic
- **Stateful Processing**: Maintain state across DNS queries for complex policy enforcement

## Quickstart

1. Download or clone the repository
2. Edit a copy of the [`config.toml`](config.toml) configuration file
3. Run EtchDNS:

```sh
etchdns -c /path/to/config.toml
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
# Blocklist configuration
nx_zones_file = "nx_zones.txt"
```

Block malicious domains, ads, or unwanted content by configuring the `nx_zones.txt` file with domains that should return NXDOMAIN responses.

EtchDNS can be used as an intermediary between a DNSCrypt server proxy (like https://github.com/DNSCrypt/encrypted-dns-server) and your resolver to reduce load and enhance reliability.

### Custom DNS Processing with WebAssembly

Implement advanced DNS processing logic:

```toml
# WebAssembly hooks
hooks_wasm_file = "hooks.wasm"
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

### WebAssembly Extensions (WIP)

> **Note**: The WebAssembly extension system is currently under active development. While functional, expect API changes and additional features in future releases.

One of EtchDNS's most powerful features is its ability to be extended through WebAssembly modules. This allows you to implement custom DNS processing logic in any language that compiles to WebAssembly, including:

- C/C++
- Zig
- AssemblyScript
- Go/TinyGo
- And many others, thanks to Extism.

#### Benefits of WebAssembly Extensions:

- **Language Flexibility**: Write extensions in your preferred programming language
- **Sandboxed Execution**: Extensions run in a secure sandbox with minimal overhead
- **Hot Reloading**: Update extensions without restarting EtchDNS
- **Performance**: Near-native execution speed for complex filtering rules

#### Current Capabilities:

The current implementation supports the following hook points:

- `hook_client_query_received`: Called when a client query is received, before checking the cache

#### Example Implementation:

EtchDNS includes an example WebAssembly plugin in the [`hooks-plugin`](hooks-plugin/) directory. This demonstrates how to create a simple plugin that can influence DNS query processing.

To use WebAssembly extensions, specify the path to your compiled WASM file:

```toml
# WebAssembly hooks
hooks_wasm_file = "hooks.wasm"
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

## Security

EtchDNS includes several security features to protect both clients and upstream servers:

- **Run with minimal privileges**: Use the privilege dropping feature
- **Domain filtering**: Restrict which queries are processed
- **Rate limiting**: Prevent abuse by limiting queries per client
- **Transaction ID masking**: Protect against cache poisoning attacks

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

1. Add the WebAssembly target to your Rust toolchain:
   ```sh
   rustup target add wasm32-unknown-unknown
   ```

2. Build the example plugin or your own extension:
   ```sh
   cd hooks-plugin
   cargo build --target wasm32-unknown-unknown --release
   ```

3. The compiled WebAssembly module will be available at `target/wasm32-unknown-unknown/release/hooks_plugin.wasm`

4. Copy the WebAssembly module to your EtchDNS directory and update the configuration:
   ```sh
   cp target/wasm32-unknown-unknown/release/hooks_plugin.wasm /path/to/etchdns/hooks.wasm
   ```

For other languages, consult their respective WebAssembly compilation guides. The key requirement is that the resulting WASM module exports functions that match the hook interface defined by EtchDNS.

## License

This project is licensed under the MIT License.

---

<p align="center">
  Made with ❤️ by the EtchDNS team
</p>
