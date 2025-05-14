# EtchDNS Hooks Plugin (Zig Version)

This is a Zig implementation of the hooks plugin for EtchDNS. It provides a WebAssembly plugin that can be used to filter DNS queries based on domain names.

## Features

- Blocks queries for specific domains and their subdomains
- Logs information about received queries
- Returns REFUSED response for blocked domains

## Building

To build the plugin, you need Zig 0.11.0 or later:

```bash
# First, update the hash in build.zig.zon with the correct one
# You can get this by running the build command and copying the expected hash from the error message
zig build
```

The compiled WebAssembly module will be in `zig-out/bin/hooks-plugin.wasm`.

## Usage

To use this plugin with EtchDNS, configure the hooks section in your EtchDNS configuration file:

```toml
[hooks]
plugin_path = "/path/to/hooks-plugin.wasm"
```

## How It Works

The plugin exports a `hook_client_query_received` function that is called by EtchDNS when a DNS query is received. The function takes the client IP address and the query name as parameters and returns:

- `0` to continue processing the query normally
- `-1` to return a REFUSED response

The plugin checks if the queried domain matches or is a subdomain of any blocked domain. If it is, the plugin logs a warning and returns `-1` to refuse the query.

## Customizing Blocked Domains

To customize the list of blocked domains, modify the `blocked_domains` array in `src/main.zig` and rebuild the plugin.

## Comparison with Rust Version

This Zig implementation provides the same functionality as the Rust version but with a smaller binary size and potentially faster execution. The WebAssembly module is compiled with the `wasm32-freestanding` target, which means it doesn't require any WASI functionality.
