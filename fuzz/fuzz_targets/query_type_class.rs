#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Call the query_type_class function with the fuzzed data
    let _ = etchdns::dns_parser::query_type_class(data);
});
