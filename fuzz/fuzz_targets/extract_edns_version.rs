#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Call the extract_edns_version function with the fuzzed data
    // This will test that the function doesn't panic on malformed input
    let _ = etchdns::dns_parser::extract_edns_version(data);
});