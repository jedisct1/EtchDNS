#[cfg(test)]
mod tests {
    use crate::dns_key::DNSKey;
    use std::collections::HashMap;

    #[test]
    fn test_dns_key_equality() {
        let key1 = DNSKey::new("example.com".to_string(), 1, 1, false);
        let key2 = DNSKey::new("example.com".to_string(), 1, 1, false);
        let key3 = DNSKey::new("example.org".to_string(), 1, 1, false);
        let key4 = DNSKey::new("example.com".to_string(), 2, 1, false);
        let key5 = DNSKey::new("example.com".to_string(), 1, 2, false);
        let key6 = DNSKey::new("example.com".to_string(), 1, 1, true);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);
        assert_ne!(key1, key5);
        assert_ne!(key1, key6);
    }

    #[test]
    fn test_dns_key_hash() {
        let mut map = HashMap::new();

        let key1 = DNSKey::new("example.com".to_string(), 1, 1, false);
        let key2 = DNSKey::new("example.com".to_string(), 1, 1, false);
        let key3 = DNSKey::new("example.org".to_string(), 1, 1, false);

        map.insert(key1, "value1");
        assert_eq!(map.get(&key2), Some(&"value1"));
        assert_eq!(map.get(&key3), None);
    }

    #[test]
    fn test_normalize_name() {
        let key1 = DNSKey::new("EXAMPLE.COM".to_string(), 1, 1, false);
        let key2 = DNSKey::new("example.com".to_string(), 1, 1, false);
        let key3 = DNSKey::new("example.com.".to_string(), 1, 1, false);

        assert_eq!(key1, key2);
        assert_eq!(key1, key3);
        assert_eq!(key2, key3);

        assert_eq!(key1.name, "example.com");
        assert_eq!(key2.name, "example.com");
        assert_eq!(key3.name, "example.com");
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

    // Helper function to create a simple DNS query packet
    fn create_dns_query_packet(domain: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut packet = Vec::new();

        // DNS Header (DNS_PACKET_LEN_MIN bytes)
        // Transaction ID (2 bytes)
        packet.push(0x12);
        packet.push(0x34);

        // Flags (2 bytes) - Standard query
        packet.push(0x01);
        packet.push(0x00);

        // QDCOUNT (2 bytes) - 1 question
        packet.push(0x00);
        packet.push(0x01);

        // ANCOUNT (2 bytes) - 0 answers
        packet.push(0x00);
        packet.push(0x00);

        // NSCOUNT (2 bytes) - 0 authority records
        packet.push(0x00);
        packet.push(0x00);

        // ARCOUNT (2 bytes) - 0 additional records
        packet.push(0x00);
        packet.push(0x00);

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
