#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Call the DNSKey::from_packet function with the fuzzed data
    let _ = etchdns::dns_key::DNSKey::from_packet(data);
});
