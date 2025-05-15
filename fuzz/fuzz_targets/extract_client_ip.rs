#![no_main]

use libfuzzer_sys::fuzz_target;

// This implements our own version of extract_client_ip since the original is private
fn test_extract_client_ip(client_addr: &str) -> String {
    if let Some(ip) = client_addr.split(':').next() {
        ip.to_string()
    } else {
        "unknown".to_string()
    }
}

fuzz_target!(|data: &[u8]| {
    // Convert raw bytes to a string (if possible)
    if let Ok(addr_str) = std::str::from_utf8(data) {
        // Call our test version of extract_client_ip
        let _ = test_extract_client_ip(addr_str);
    }
});
