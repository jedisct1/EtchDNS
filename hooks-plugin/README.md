# EtchDNS WebAssembly Hooks Plugin

This is an example WebAssembly plugin for EtchDNS that implements the `hook_client_query_received` function.

## Overview

The plugin is built using the [Extism PDK](https://extism.org/docs/concepts/pdk) (Plugin Development Kit) for Rust. It demonstrates how to create a simple hook that can influence DNS query processing in EtchDNS.

## Functionality

The plugin implements a single hook function:

### `hook_client_query_received`

This function is called when a client query is received by EtchDNS, just before checking if the response is in the cache.

**Input**: JSON string with the following structure:
```json
{
  "query_name": "example.com",
  "qtype": 1,
  "qclass": 1,
  "client_ip": "192.168.1.1"
}
```

**Output**: An integer code as a string:
- `"0"` - Continue normal processing
- `"-1"` - Return a minimal response with REFUSED rcode

## Implementation Details

The plugin uses a simple rule for demonstration purposes:
- If the query is for "example.com" OR the client IP is "192.168.1.100", it returns `"-1"` to refuse the query
- For all other domains and client IPs, it returns `"0"` to continue normal processing

## Building the Plugin

To build the WebAssembly plugin:

```bash
# Add the WebAssembly target
rustup target add wasm32-unknown-unknown

# Build the plugin
cargo build --target wasm32-unknown-unknown --release
```

The compiled WebAssembly module will be available at `target/wasm32-unknown-unknown/release/hooks_plugin.wasm`.

## Using the Plugin with EtchDNS

1. Copy the WebAssembly module to the EtchDNS directory:
   ```bash
   cp target/wasm32-unknown-unknown/release/hooks_plugin.wasm /path/to/etchdns/hooks.wasm
   ```

2. Update the EtchDNS configuration file (`config.toml`) to use the plugin:
   ```toml
   # Path to a WebAssembly file containing hook implementations
   hooks_wasm_file = "hooks.wasm"
   ```

3. Start EtchDNS, and it will load the WebAssembly plugin.

## Extending the Plugin

To add more functionality to the plugin:

1. Add new hook functions in `lib.rs` using the `#[plugin_fn]` attribute
2. Implement the logic for the new hooks
3. Rebuild the plugin
4. Update EtchDNS to call the new hook functions

## License

This example plugin is provided under the same license as EtchDNS.
