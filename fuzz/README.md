# Fuzzing Tests for EtchDNS

This directory contains fuzzing tests for the EtchDNS DNS parsers using `cargo-fuzz`.

## Prerequisites

You need to have `cargo-fuzz` installed:

```bash
cargo install cargo-fuzz
```

## Available Fuzz Targets

The following fuzz targets are available:

1. `validate_dns_packet` - Tests the `dns_parser::validate_dns_packet` function
2. `qname` - Tests the `dns_parser::qname` function
3. `query_type_class` - Tests the `dns_parser::query_type_class` function
4. `is_dnssec_requested` - Tests the `dns_parser::is_dnssec_requested` function
5. `dns_key_from_packet` - Tests the `DNSKey::from_packet` function

## Running the Fuzzing Tests

To run a specific fuzz target:

```bash
# Run the validate_dns_packet fuzzer
cargo fuzz run validate_dns_packet

# Run the qname fuzzer
cargo fuzz run qname

# Run the query_type_class fuzzer
cargo fuzz run query_type_class

# Run the is_dnssec_requested fuzzer
cargo fuzz run is_dnssec_requested

# Run the dns_key_from_packet fuzzer
cargo fuzz run dns_key_from_packet
```

## Corpus

Each fuzz target has its own corpus directory in `fuzz/corpus/<target_name>/`. The corpus contains initial valid DNS packets to help the fuzzer find interesting inputs.

The corpus is automatically generated when building the fuzz targets.

## Customizing Fuzzing Runs

You can customize the fuzzing run with additional options:

```bash
# Run with a time limit (e.g., 60 seconds)
cargo fuzz run validate_dns_packet -- -max_total_time=60

# Run with a specific number of iterations
cargo fuzz run validate_dns_packet -- -runs=1000000

# Run with more detailed output
cargo fuzz run validate_dns_packet -- -v
```

## Handling Crashes

When a fuzzer finds a crash, it will save the input that caused the crash in `fuzz/artifacts/<target_name>/`. You can reproduce the crash with:

```bash
cargo fuzz run <target_name> <path_to_artifact>
```

## Adding New Fuzz Targets

To add a new fuzz target:

1. Add a new entry to `fuzz/Cargo.toml`
2. Create a new file in `fuzz/fuzz_targets/`
3. Update the corpus generator in `fuzz/generate_corpus.rs` if needed
