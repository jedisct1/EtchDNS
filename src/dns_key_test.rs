#[cfg(test)]
mod tests {
    use crate::dns_key::DNSKey;
    use crate::errors::DnsError;
    use std::collections::HashMap;

    #[test]
    fn test_dns_key_equality() {
        let key1 = DNSKey::new("example.com".to_string(), 1, 1, false).unwrap();
        let key2 = DNSKey::new("example.com".to_string(), 1, 1, false).unwrap();
        let key3 = DNSKey::new("example.org".to_string(), 1, 1, false).unwrap();
        let key4 = DNSKey::new("example.com".to_string(), 2, 1, false).unwrap();
        let key5 = DNSKey::new("example.com".to_string(), 1, 2, false).unwrap();
        let key6 = DNSKey::new("example.com".to_string(), 1, 1, true).unwrap();

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);
        assert_ne!(key1, key5);
        assert_ne!(key1, key6);
    }

    #[test]
    fn test_dns_key_hash() {
        let mut map = HashMap::new();

        let key1 = DNSKey::new("example.com".to_string(), 1, 1, false).unwrap();
        let key2 = DNSKey::new("example.com".to_string(), 1, 1, false).unwrap();
        let key3 = DNSKey::new("example.org".to_string(), 1, 1, false).unwrap();

        map.insert(key1, "value1");
        assert_eq!(map.get(&key2), Some(&"value1"));
        assert_eq!(map.get(&key3), None);
    }

    #[test]
    fn test_normalize_name() {
        // Test basic normalization
        let key1 = DNSKey::new("EXAMPLE.COM".to_string(), 1, 1, false).unwrap();
        let key2 = DNSKey::new("example.com".to_string(), 1, 1, false).unwrap();
        let key3 = DNSKey::new("example.com.".to_string(), 1, 1, false).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1, key3);
        assert_eq!(key2, key3);

        assert_eq!(key1.name, "example.com");
        assert_eq!(key2.name, "example.com");
        assert_eq!(key3.name, "example.com");

        // Test direct calls to normalize_name for additional edge cases

        // Trailing dots - now normalized
        assert_eq!(
            DNSKey::normalize_name("example.com.").unwrap(),
            "example.com"
        );

        // Root domain cases
        assert_eq!(DNSKey::normalize_name(".").unwrap(), ".");
        assert_eq!(DNSKey::normalize_name("").unwrap(), ".");
    }

    #[test]
    fn test_normalize_name_errors() {
        // Multiple consecutive dots in the middle - now returns error
        match DNSKey::normalize_name("example..com") {
            Err(DnsError::InvalidDomainName(_)) => { /* Expected error */ }
            other => panic!("Expected InvalidDomainName error, got {:?}", other),
        }

        // Multiple consecutive dots - now returns error
        match DNSKey::normalize_name("example...com") {
            Err(DnsError::InvalidDomainName(_)) => { /* Expected error */ }
            other => panic!("Expected InvalidDomainName error, got {:?}", other),
        }

        // Multiple leading and trailing dots with consecutive dots in the middle - now returns error
        match DNSKey::normalize_name("...example...com...") {
            Err(DnsError::InvalidDomainName(_)) => { /* Expected error */ }
            other => panic!("Expected InvalidDomainName error, got {:?}", other),
        }

        // Domain starting with a dot - now returns error (when not just root domain)
        match DNSKey::normalize_name(".example.com") {
            Err(DnsError::InvalidDomainName(_)) => { /* Expected error */ }
            other => panic!("Expected InvalidDomainName error, got {:?}", other),
        }

        // Domain starting with multiple dots - now returns error (when not just root domain)
        match DNSKey::normalize_name("..example.com") {
            Err(DnsError::InvalidDomainName(_)) => { /* Expected error */ }
            other => panic!("Expected InvalidDomainName error, got {:?}", other),
        }
    }

    #[test]
    fn test_from_packet() {
        // Create a simple DNS query packet for example.com A record
        let packet = create_dns_query_packet("example.com", 1, 1);

        // Parse the packet into a DNSKey
        let key = DNSKey::from_packet(&packet).unwrap();

        // Verify the key properties
        assert_eq!(key.name, "example.com");
        assert_eq!(key.qtype, 1);
        assert_eq!(key.qclass, 1);
        assert!(!key.dnssec);
    }

    #[test]
    fn test_new_with_invalid_name() {
        // Test that DNSKey::new rejects invalid domain names with consecutive dots
        let domain_with_consecutive_dots = "example..com".to_string();
        match DNSKey::new(domain_with_consecutive_dots, 1, 1, false) {
            Err(DnsError::InvalidDomainName(_)) => { /* Expected error */ }
            other => panic!("Expected InvalidDomainName error, got {:?}", other),
        }
    }

    // Helper function to create a simple DNS query packet
    fn create_dns_query_packet(domain: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        // Start with DNS header
        let mut packet = vec![
            // Transaction ID (2 bytes)
            0x12, 0x34, // Flags (2 bytes) - Standard query
            0x01, 0x00, // QDCOUNT (2 bytes) - 1 question
            0x00, 0x01, // ANCOUNT (2 bytes) - 0 answers
            0x00, 0x00, // NSCOUNT (2 bytes) - 0 authority records
            0x00, 0x00, // ARCOUNT (2 bytes) - 0 additional records
            0x00, 0x00,
        ];

        // Question section
        // Split the domain into labels
        let labels: Vec<&str> = domain.split('.').collect();
        for label in labels {
            // Add the length of the label
            packet.push(label.len() as u8);
            // Add the label
            for byte in label.bytes() {
                packet.push(byte);
            }
        }

        // Add the terminating zero
        packet.push(0x00);

        // Add QTYPE (2 bytes)
        packet.push((qtype >> 8) as u8);
        packet.push(qtype as u8);

        // Add QCLASS (2 bytes)
        packet.push((qclass >> 8) as u8);
        packet.push(qclass as u8);

        packet
    }
}
