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

fn main() {
    // Create corpus directories if they don't exist
    let targets = [
        "validate_dns_packet",
        "qname",
        "query_type_class",
        "is_dnssec_requested",
        "dns_key_from_packet",
    ];

    for target in &targets {
        let corpus_dir = format!("corpus/{}", target);
        fs::create_dir_all(&corpus_dir).expect("Failed to create corpus directory");

        // Generate some valid DNS packets for the corpus
        let domains = ["example.com", "test.org", "subdomain.example.net"];
        let qtypes = [1, 2, 5, 15, 28]; // A, NS, CNAME, MX, AAAA
        let qclasses = [1]; // IN
        let dnssec_options = [false, true];

        let mut sample_id = 1;
        for domain in &domains {
            for &qtype in &qtypes {
                for &qclass in &qclasses {
                    for &dnssec in &dnssec_options {
                        let packet = create_dns_query(domain, qtype, qclass, dnssec);
                        let file_path = format!("{}/sample_{}", corpus_dir, sample_id);
                        fs::write(&file_path, &packet).expect("Failed to write corpus sample");
                        sample_id += 1;
                    }
                }
            }
        }

        println!("Generated {} corpus samples for {}", sample_id - 1, target);
    }
}
