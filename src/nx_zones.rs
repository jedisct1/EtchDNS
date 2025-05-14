use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

/// Manages a list of nonexistent DNS zones
#[derive(Clone)]
pub struct NxZones {
    /// Set of nonexistent domain names
    zones: HashSet<String>,
}

impl NxZones {
    /// Create a new empty NxZones
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            zones: HashSet::new(),
        }
    }

    /// Load nonexistent zones from a file
    ///
    /// Each line in the file should contain a single domain name.
    /// Empty lines and lines starting with '#' are ignored.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut zones = HashSet::new();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Normalize domain name (lowercase, ensure it ends with a dot)
            let mut domain = trimmed.to_lowercase();
            if !domain.ends_with('.') {
                domain.push('.');
            }

            zones.insert(domain);
        }

        Ok(Self { zones })
    }

    /// Check if a domain is in the nonexistent zones list
    ///
    /// A domain is considered nonexistent if it matches or is a subdomain of a nonexistent zone.
    pub fn is_nonexistent(&self, domain: &str) -> bool {
        // If no zones are defined, no domains are nonexistent
        if self.zones.is_empty() {
            return false;
        }

        // Normalize the domain (lowercase, ensure it ends with a dot)
        let mut normalized = domain.to_lowercase();
        if !normalized.ends_with('.') {
            normalized.push('.');
        }

        // Check if the domain is in the nonexistent zones
        if self.zones.contains(&normalized) {
            return true;
        }

        // Check if the domain is a subdomain of a nonexistent zone
        let mut parts: Vec<&str> = normalized.split('.').collect();

        // Start removing subdomains one by one to check parent domains
        while parts.len() > 2 {
            // Keep at least "domain.tld."
            parts.remove(0);
            let parent = parts.join(".");
            if self.zones.contains(&parent) {
                return true;
            }
        }

        false
    }

    /// Get the number of nonexistent zones
    pub fn len(&self) -> usize {
        self.zones.len()
    }

    /// Check if there are no nonexistent zones
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_is_nonexistent_empty() {
        let zones = NxZones::new();
        assert!(!zones.is_nonexistent("example.com"));
        assert!(!zones.is_nonexistent("test.example.com"));
    }

    #[test]
    fn test_is_nonexistent_exact_match() {
        let mut zones = NxZones::new();
        zones.zones.insert("example.com.".to_string());

        assert!(zones.is_nonexistent("example.com"));
        assert!(zones.is_nonexistent("example.com."));
        assert!(!zones.is_nonexistent("test.com"));
    }

    #[test]
    fn test_is_nonexistent_subdomain() {
        let mut zones = NxZones::new();
        zones.zones.insert("example.com.".to_string());

        assert!(zones.is_nonexistent("sub.example.com"));
        assert!(zones.is_nonexistent("deep.sub.example.com"));
        assert!(!zones.is_nonexistent("notexample.com"));
    }

    #[test]
    fn test_load_from_file() -> io::Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "nonexistent.com")?;
        writeln!(file, "# Comment line")?;
        writeln!(file)?;
        writeln!(file, "invalid.org.")?;

        let zones = NxZones::load_from_file(file.path())?;

        assert_eq!(zones.len(), 2);
        assert!(zones.is_nonexistent("nonexistent.com"));
        assert!(zones.is_nonexistent("sub.nonexistent.com"));
        assert!(zones.is_nonexistent("invalid.org"));
        assert!(!zones.is_nonexistent("other.com"));

        Ok(())
    }
}
