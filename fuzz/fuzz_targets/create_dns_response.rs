#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // If we have at least 1 byte to use as RCODE
    if !data.is_empty() {
        // Use the first byte as RCODE and rest as packet data
        let rcode = data[0] % 16; // RCODE is 4 bits (0-15)
        let query_data = &data[1..];

        // Call the create_dns_response function
        let _ = etchdns::dns_processor::create_dns_response(query_data, rcode, None);
    }
});
