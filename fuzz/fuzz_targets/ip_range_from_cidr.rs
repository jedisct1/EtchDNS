#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Convert raw bytes to a string (if possible)
    if let Ok(cidr_str) = std::str::from_utf8(data) {
        // Try to parse the string as a CIDR notation
        let _ = etchdns::ip_validator::IpRange::from_cidr(cidr_str);
    }
});
