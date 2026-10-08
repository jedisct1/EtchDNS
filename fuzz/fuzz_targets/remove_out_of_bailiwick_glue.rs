#![no_main]

use etchdns::dns_parser::{remove_out_of_bailiwick_glue, validate_dns_packet};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let was_valid = validate_dns_packet(data).is_ok();
    let mut packet = data.to_vec();
    match remove_out_of_bailiwick_glue(&mut packet) {
        Ok(0) | Err(_) => assert_eq!(packet, data),
        Ok(_) if was_valid => assert!(validate_dns_packet(&packet).is_ok()),
        Ok(_) => {}
    }
});
