use std::fs;
use std::path::Path;

// Function to create a simple DNS query packet
fn create_dns_query(domain: &str, qtype: u16, qclass: u16, dnssec: bool) -> Vec<u8> {
    let mut packet = Vec::new();

    // DNS Header (12 bytes)
    // Transaction ID (2 bytes)
    packet.push(0x12);
    packet.push(0x34);

    // Flags (2 bytes) - Standard query with RD bit set
    let mut flags = 0x0100; // RD bit set
    if dnssec {
        flags |= 0x0010; // CD bit set for DNSSEC
    }
    packet.push((flags >> 8) as u8);
    packet.push(flags as u8);

    // QDCOUNT (2 bytes) - 1 question
    packet.push(0x00);
    packet.push(0x01);

    // ANCOUNT (2 bytes) - 0 answers
    packet.push(0x00);
    packet.push(0x00);

    // NSCOUNT (2 bytes) - 0 authority records
    packet.push(0x00);
    packet.push(0x00);

    // ARCOUNT (2 bytes) - 0 additional records (will be updated if EDNS is added)
    packet.push(0x00);
    packet.push(0x00);

    // Question section
    // Split domain into labels
    let labels: Vec<&str> = domain.split('.').collect();
    for label in labels {
        if !label.is_empty() {
            packet.push(label.len() as u8);
            for b in label.bytes() {
                packet.push(b);
            }
        }
    }
    // Root label
    packet.push(0x00);

    // QTYPE (2 bytes)
    packet.push((qtype >> 8) as u8);
    packet.push(qtype as u8);

    // QCLASS (2 bytes)
    packet.push((qclass >> 8) as u8);
    packet.push(qclass as u8);

    // If DNSSEC is requested, add an OPT record
    if dnssec {
        // Update ARCOUNT
        packet[11] = 0x01;

        // Add OPT record
        // Root domain name
        packet.push(0x00);

        // TYPE = OPT (41)
        packet.push(0x00);
        packet.push(0x29);

        // CLASS field is the maximum UDP payload size (4096)
        packet.push(0x10);
        packet.push(0x00);

        // TTL field (extended RCODE and flags)
        packet.push(0x00); // Extended RCODE
        packet.push(0x00); // Version
        packet.push(0x80); // High flags - DO bit set
        packet.push(0x00); // Low flags

        // RDLEN
        packet.push(0x00);
        packet.push(0x00);
    }

    packet
}

// Function to create sample data for IP validator fuzzing
fn create_ip_validator_samples() -> Vec<String> {
    vec![
        // Valid IPs
        "8.8.8.8".to_string(),
        "1.1.1.1".to_string(),
        "2001:db8:85a3::8a2e:370:7334".to_string(),
        "2606:4700:4700::1111".to_string(),
        // Invalid IPs
        "256.0.0.1".to_string(),
        "8.8.8".to_string(),
        "8.8.8.8.8".to_string(),
        "2001:db8:85a3:::8a2e:370:7334".to_string(),
        // Reserved IPs
        "0.0.0.0".to_string(),
        "127.0.0.1".to_string(),
        "10.0.0.1".to_string(),
        "172.16.0.1".to_string(),
        "192.168.1.1".to_string(),
        "169.254.1.1".to_string(),
        "224.0.0.1".to_string(),
        "255.255.255.255".to_string(),
        "::".to_string(),
        "::1".to_string(),
        "fe80::1".to_string(),
        "fc00::1".to_string(),
        "ff00::1".to_string(),
        // Socket addresses
        "8.8.8.8:53".to_string(),
        "1.1.1.1:443".to_string(),
        "2001:db8:85a3::8a2e:370:7334:80".to_string(),
        "192.168.1.1:8080".to_string(),
        "[2001:db8::1]:53".to_string(),
        // Invalid socket addresses
        "8.8.8.8:".to_string(),
        "8.8.8.8:65536".to_string(),
        "8.8.8.8:-1".to_string(),
        "2001:db8::1:53:extra".to_string(),
    ]
}

// Function to create sample data for IP range CIDR parsing
fn create_ip_range_samples() -> Vec<String> {
    vec![
        // Valid CIDR notations
        "192.168.0.0/16".to_string(),
        "10.0.0.0/8".to_string(),
        "172.16.0.0/12".to_string(),
        "8.8.8.0/24".to_string(),
        "0.0.0.0/0".to_string(),
        "2001:db8::/32".to_string(),
        "2001:db8:1234::/48".to_string(),
        "2606:4700:4700::/64".to_string(),
        "::/0".to_string(),
        // Invalid CIDR notations
        "192.168.0.0".to_string(),
        "192.168.0.0/".to_string(),
        "192.168.0.0/33".to_string(),
        "2001:db8::/129".to_string(),
        "not-an-ip/24".to_string(),
        "192.168.0.0/not-a-prefix".to_string(),
        "192.168.0.0/-1".to_string(),
        "::/x".to_string(),
    ]
}

// Function to create sample data for extract_client_ip
fn create_client_ip_samples() -> Vec<String> {
    vec![
        // Valid client addresses
        "192.168.1.1:12345".to_string(),
        "8.8.8.8:53".to_string(),
        "2001:db8::1:54321".to_string(),
        "[2001:db8::1]:54321".to_string(),
        // Invalid client addresses
        "192.168.1.1".to_string(), // Missing port
        ":8080".to_string(),       // Missing IP
        "invalid-ip:8080".to_string(),
        "".to_string(), // Empty string
    ]
}

// Function to generate sample DNS responses with various RCODEs
fn create_dns_response_samples() -> Vec<(u8, Vec<u8>)> {
    let rcodes = vec![
        0, // NOERROR
        1, // FORMERR
        2, // SERVFAIL
        3, // NXDOMAIN
        4, // NOTIMP
        5, // REFUSED
    ];

    let mut samples = Vec::new();

    for &rcode in &rcodes {
        // Create a few DNS packets to use with different RCODEs
        for domain in &["example.com", "test.org"] {
            for qtype in &[1, 28] {
                // A and AAAA
                let packet = create_dns_query(domain, *qtype, 1, false);
                samples.push((rcode, packet));
            }
        }

        // Also add some malformed packets
        let malformed = vec![
            vec![0, 1, 2, 3, 4, 5], // Too short
            vec![0; 512],           // All zeros
            (0..255).collect(),     // Sequential bytes
        ];

        for packet in malformed {
            samples.push((rcode, packet));
        }
    }

    samples
}

// Function to generate sample IP addresses for rate limiter
fn create_ip_addresses() -> Vec<Vec<u8>> {
    let mut samples = Vec::new();

    // IPv4 addresses in binary form
    let ipv4_samples = vec![
        vec![0, 127, 0, 0, 1],   // 127.0.0.1 (loopback)
        vec![0, 192, 168, 1, 1], // 192.168.1.1 (private)
        vec![0, 8, 8, 8, 8],     // 8.8.8.8 (Google DNS)
        vec![0, 1, 1, 1, 1],     // 1.1.1.1 (Cloudflare DNS)
    ];

    // IPv6 addresses in binary form
    let ipv6_samples = vec![
        // ::1 (loopback)
        vec![1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        // 2001:db8::1 (documentation)
        vec![
            1, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ],
        // 2606:4700:4700::1111 (Cloudflare DNS)
        vec![
            1, 0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ],
    ];

    samples.extend(ipv4_samples);
    samples.extend(ipv6_samples);

    samples
}

fn main() {
    // Create corpus directories if they don't exist
    let targets = [
        "validate_dns_packet",
        "qname",
        "query_type_class",
        "is_dnssec_requested",
        "dns_key_from_packet",
        "ip_validator_validate",
        "ip_range_from_cidr",
        "create_dns_response",
        "extract_client_ip",
        "rate_limiter_is_allowed",
    ];

    for target in &targets {
        let corpus_dir = format!("corpus/{}", target);
        fs::create_dir_all(&corpus_dir).expect("Failed to create corpus directory");

        let mut sample_id = 1;

        match *target {
            "ip_validator_validate" => {
                // Generate sample IPs and socket addresses
                for sample in create_ip_validator_samples() {
                    let file_path = format!("{}/sample_{}", corpus_dir, sample_id);
                    fs::write(&file_path, sample).expect("Failed to write corpus sample");
                    sample_id += 1;
                }
            }
            "ip_range_from_cidr" => {
                // Generate sample CIDR notations
                for sample in create_ip_range_samples() {
                    let file_path = format!("{}/sample_{}", corpus_dir, sample_id);
                    fs::write(&file_path, sample).expect("Failed to write corpus sample");
                    sample_id += 1;
                }
            }
            "create_dns_response" => {
                // Generate sample DNS packets with various RCODEs
                for (rcode, packet) in create_dns_response_samples() {
                    let mut data = Vec::with_capacity(packet.len() + 1);
                    data.push(rcode);
                    data.extend_from_slice(&packet);

                    let file_path = format!("{}/sample_{}", corpus_dir, sample_id);
                    fs::write(&file_path, data).expect("Failed to write corpus sample");
                    sample_id += 1;
                }
            }
            "extract_client_ip" => {
                // Generate sample client IP address strings
                for sample in create_client_ip_samples() {
                    let file_path = format!("{}/sample_{}", corpus_dir, sample_id);
                    fs::write(&file_path, sample).expect("Failed to write corpus sample");
                    sample_id += 1;
                }
            }
            "rate_limiter_is_allowed" => {
                // Generate sample IP addresses for rate limiter
                for sample in create_ip_addresses() {
                    let file_path = format!("{}/sample_{}", corpus_dir, sample_id);
                    fs::write(&file_path, sample).expect("Failed to write corpus sample");
                    sample_id += 1;
                }
            }
            _ => {
                // Generate standard DNS packets for the existing targets
                let domains = ["example.com", "test.org", "subdomain.example.net"];
                let qtypes = [1, 2, 5, 15, 28]; // A, NS, CNAME, MX, AAAA
                let qclasses = [1]; // IN
                let dnssec_options = [false, true];

                for domain in &domains {
                    for &qtype in &qtypes {
                        for &qclass in &qclasses {
                            for &dnssec in &dnssec_options {
                                let packet = create_dns_query(domain, qtype, qclass, dnssec);
                                let file_path = format!("{}/sample_{}", corpus_dir, sample_id);
                                fs::write(&file_path, &packet)
                                    .expect("Failed to write corpus sample");
                                sample_id += 1;
                            }
                        }
                    }
                }
            }
        }

        println!("Generated {} corpus samples for {}", sample_id - 1, target);
    }
}
