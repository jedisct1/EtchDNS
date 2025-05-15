#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Convert raw bytes to a string (if possible)
    if let Ok(ip_str) = std::str::from_utf8(data) {
        // Create a default IP validator
        let validator = etchdns::ip_validator::IpValidator::new();

        // Try to validate the string as an IP address
        let _ = validator.validate_ip_str(ip_str);

        // Also try validating as a socket address
        let _ = validator.validate_socket_addr_str(ip_str);
    }
});
