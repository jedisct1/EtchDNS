use crate::dns_key::DNSKey;
use log::{debug, error, info};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// QueryLogger handles logging DNS queries to a file
#[derive(Debug, Clone)]
pub struct QueryLogger {
    inner: Arc<Mutex<QueryLoggerInner>>,
}

/// Inner implementation of QueryLogger
#[derive(Debug)]
struct QueryLoggerInner {
    /// The file to log to
    file: Option<File>,
    /// The path to the log file
    log_file_path: Option<PathBuf>,
    /// Whether to include the timestamp in the log
    include_timestamp: bool,
    /// Whether to include the client address in the log
    include_client_addr: bool,
    /// Whether to include the query type in the log
    include_query_type: bool,
    /// Whether to include the query class in the log
    include_query_class: bool,
}

impl QueryLogger {
    /// Create a new QueryLogger
    pub fn new(
        log_file_path: Option<String>,
        include_timestamp: bool,
        include_client_addr: bool,
        include_query_type: bool,
        include_query_class: bool,
    ) -> Self {
        let file = match log_file_path {
            Some(ref path) => {
                let path_buf = PathBuf::from(path);
                match OpenOptions::new().create(true).append(true).open(&path_buf) {
                    Ok(file) => {
                        info!("Query logging enabled to file: {path}");
                        Some(file)
                    }
                    Err(e) => {
                        error!("Failed to open query log file {path}: {e}");
                        None
                    }
                }
            }
            None => None,
        };

        Self {
            inner: Arc::new(Mutex::new(QueryLoggerInner {
                file,
                log_file_path: log_file_path.map(PathBuf::from),
                include_timestamp,
                include_client_addr,
                include_query_type,
                include_query_class,
            })),
        }
    }

    /// Log a DNS query
    pub async fn log_query(&self, key: &DNSKey, client_addr: &str) {
        let mut inner = self.inner.lock().await;

        if inner.file.is_none() {
            return;
        }

        // Copy configuration values to avoid borrow issues
        let include_timestamp = inner.include_timestamp;
        let include_client_addr = inner.include_client_addr;
        let include_query_type = inner.include_query_type;
        let include_query_class = inner.include_query_class;
        let log_file_path = inner.log_file_path.clone();

        // Build the log line
        let mut log_line = String::new();

        // Add timestamp if enabled
        if include_timestamp {
            if let Ok(time) = SystemTime::now().duration_since(UNIX_EPOCH) {
                log_line.push_str(&format!("[{}] ", time.as_secs()));
            }
        }

        // Add client address if enabled
        if include_client_addr {
            log_line.push_str(&format!("{client_addr} "));
        }

        // Always include the domain name
        log_line.push_str(&key.name);

        // Add query type if enabled
        if include_query_type {
            log_line.push_str(&format!(" TYPE{}", key.qtype));
        }

        // Add query class if enabled
        if include_query_class {
            log_line.push_str(&format!(" CLASS{}", key.qclass));
        }

        // Add newline
        log_line.push('\n');

        // Write to file
        if let Some(file) = &mut inner.file {
            if let Err(e) = file.write_all(log_line.as_bytes()) {
                error!("Failed to write to query log file: {e}");

                // Try to reopen the file if it was closed or moved
                if let Some(path) = &log_file_path {
                    match OpenOptions::new().create(true).append(true).open(path) {
                        Ok(new_file) => {
                            debug!("Reopened query log file: {}", path.display());
                            inner.file = Some(new_file);

                            // Try writing again
                            if let Some(file) = &mut inner.file {
                                if let Err(e) = file.write_all(log_line.as_bytes()) {
                                    error!("Failed to write to reopened query log file: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to reopen query log file {}: {}", path.display(), e);
                            inner.file = None;
                        }
                    }
                }
            }
        }
    }

    /// Check if query logging is enabled
    #[allow(dead_code)]
    pub async fn is_enabled(&self) -> bool {
        let inner = self.inner.lock().await;
        inner.file.is_some()
    }
}
