use std::hash::{Hash, Hasher};

use crate::dns_parser;
use crate::errors::{DnsError, DnsResult};

/// A structure representing a DNS query key for caching purposes.
///
/// This structure contains the normalized query name, query type, query class,
/// and whether DNSSEC is requested. It can be used as a key in a hash map
/// to cache DNS responses.
#[derive(Debug, Clone, Eq)]
pub struct DNSKey {
    /// The normalized query name (lowercase, no trailing dot)
    pub name: String,
    /// The query type (e.g., A, AAAA, MX)
    pub qtype: u16,
    /// The query class (usually IN)
    pub qclass: u16,
    /// Whether DNSSEC is requested
    pub dnssec: bool,
}

impl DNSKey {
    /// Creates a new DNSKey with the given parameters
    pub fn new(name: String, qtype: u16, qclass: u16, dnssec: bool) -> Self {
        // Normalize the name (lowercase, no trailing dot)
        let normalized_name = Self::normalize_name(&name);

        DNSKey {
            name: normalized_name,
            qtype,
            qclass,
            dnssec,
        }
    }

    /// Creates a DNSKey from a DNS packet
    pub fn from_packet(packet: &[u8]) -> DnsResult<Self> {
        // Validate the packet first
        dns_parser::validate_dns_packet(packet)?;

        // Extract the query name using dns_parser's qname function
        let qname_bytes = dns_parser::qname(packet)?;
        let qname = match std::str::from_utf8(&qname_bytes) {
            Ok(s) => s.to_string(),
            Err(_) => {
                return Err(DnsError::InvalidDomainName(
                    "Invalid UTF-8 in query name".to_string(),
                ));
            }
        };

        // Extract the query type and class
        let (qtype, qclass) = dns_parser::query_type_class(packet)?;

        // Check if DNSSEC is requested
        let dnssec = dns_parser::is_dnssec_requested(packet)?;

        Ok(DNSKey::new(qname, qtype, qclass, dnssec))
    }

    /// Normalizes a domain name by converting it to lowercase and removing the trailing dot
    ///
    /// Also validates that the domain name is not too long.
    /// This is a public method that can be called from outside the struct.
    pub fn normalize_name(name: &str) -> String {
        // Check if the domain name is too long
        if name.len() > crate::dns_parser::DNS_MAX_HOSTNAME_SIZE {
            // Log a warning but proceed with truncation
            log::warn!(
                "Domain name too long: {} bytes (max {}), truncating",
                name.len(),
                crate::dns_parser::DNS_MAX_HOSTNAME_SIZE
            );
        }

        let mut normalized = name.to_lowercase();
        if normalized.ends_with('.') {
            normalized.pop();
        }

        // Ensure the normalized name doesn't exceed the maximum length
        if normalized.len() > crate::dns_parser::DNS_MAX_HOSTNAME_SIZE {
            normalized.truncate(crate::dns_parser::DNS_MAX_HOSTNAME_SIZE);
        }

        normalized
    }
}

impl PartialEq for DNSKey {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.qtype == other.qtype
            && self.qclass == other.qclass
            && self.dnssec == other.dnssec
    }
}

impl Hash for DNSKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.qtype.hash(state);
        self.qclass.hash(state);
        self.dnssec.hash(state);
    }
}
