#!/bin/bash

set -euo pipefail

# Make sure the Extism CLI is installed
if ! command -v extism &> /dev/null; then
    echo "Extism CLI not found. Please install it from https://github.com/extism/cli"
    exit 1
fi

# Build the plugin
echo "Building the plugin..."
zig build

# Test with allowed domain
echo -e "\nTesting with allowed domain (google.com):"
allowed_output=$(extism call ./zig-out/bin/etchdns-plugin.wasm hook_client_query_received \
    --input='{"client_ip":"192.168.1.100","query_name":"google.com"}' \
    --log-level=error)
test "$allowed_output" = "0"

# Test with blocked domain
echo -e "\nTesting with blocked domain (example.com):"
blocked_output=$(extism call ./zig-out/bin/etchdns-plugin.wasm hook_client_query_received \
    --input='{"client_ip":"192.168.1.100","query_name":"example.com"}' \
    --log-level=error)
test "$blocked_output" = "-1"

# Test with subdomain of blocked domain
echo -e "\nTesting with subdomain of blocked domain (www.example.com):"
subdomain_output=$(extism call ./zig-out/bin/etchdns-plugin.wasm hook_client_query_received \
    --input='{"client_ip":"192.168.1.100","query_name":"www.example.com"}' \
    --log-level=error)
test "$subdomain_output" = "-1"

echo -e "\nTests completed."
