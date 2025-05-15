use crate::dns_key::DNSKey;
use log::{debug, error, info};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
    /// Maximum size in bytes before rotating log files (0 to disable size-based rotation)
    rotation_size: usize,
    /// Time interval for log rotation ("hourly", "daily", "weekly", "monthly")
    rotation_interval: String,
    /// Number of rotated log files to keep
    rotation_count: usize,
    /// Whether to compress rotated log files
    compression: bool,
    /// Last rotation time
    last_rotation_time: SystemTime,
    /// Current log file size
    current_size: usize,
}

impl QueryLogger {
    /// Check if log rotation is needed and perform rotation if necessary
    async fn check_rotation(&self) -> io::Result<()> {
        let mut inner = self.inner.lock().await;

        // Check if we need to rotate based on file size
        if inner.rotation_size > 0 && inner.current_size >= inner.rotation_size {
            debug!(
                "Log rotation triggered: file size {}/{}",
                inner.current_size, inner.rotation_size
            );
            self.rotate_log(&mut inner).await?;
            return Ok(());
        }

        // Check if we need to rotate based on time interval
        if !inner.rotation_interval.is_empty() && inner.rotation_interval != "never" {
            let now = SystemTime::now();

            // Calculate the next rotation time based on the interval
            let should_rotate = match inner.rotation_interval.as_str() {
                "hourly" => {
                    // Rotate if we've crossed an hour boundary
                    let elapsed = now
                        .duration_since(inner.last_rotation_time)
                        .unwrap_or(Duration::from_secs(0));
                    elapsed.as_secs() >= 3600 // 1 hour in seconds
                }
                "daily" => {
                    // Rotate if we've crossed a day boundary
                    let elapsed = now
                        .duration_since(inner.last_rotation_time)
                        .unwrap_or(Duration::from_secs(0));
                    elapsed.as_secs() >= 86400 // 24 hours in seconds
                }
                "weekly" => {
                    // Rotate if we've crossed a week boundary
                    let elapsed = now
                        .duration_since(inner.last_rotation_time)
                        .unwrap_or(Duration::from_secs(0));
                    elapsed.as_secs() >= 604800 // 7 days in seconds
                }
                "monthly" => {
                    // This is approximate since months vary in length
                    let elapsed = now
                        .duration_since(inner.last_rotation_time)
                        .unwrap_or(Duration::from_secs(0));
                    elapsed.as_secs() >= 2592000 // ~30 days in seconds
                }
                _ => false,
            };

            if should_rotate {
                debug!(
                    "Log rotation triggered: time interval {}",
                    inner.rotation_interval
                );
                self.rotate_log(&mut inner).await?;
                return Ok(());
            }
        }

        Ok(())
    }

    /// Rotate the log file
    async fn rotate_log(&self, inner: &mut QueryLoggerInner) -> io::Result<()> {
        // Can't rotate if we don't have a log file
        if inner.file.is_none() || inner.log_file_path.is_none() {
            return Ok(());
        }

        // Close the current log file
        inner.file = None;

        let log_path = inner.log_file_path.as_ref().unwrap();
        let log_path_str = log_path.to_string_lossy();

        // Manage rotation - first remove old files if we're at the limit
        if inner.rotation_count > 0 {
            // Look for existing rotated files
            let log_dir = log_path.parent().unwrap_or_else(|| Path::new("."));
            let log_name = log_path.file_name().unwrap_or_default().to_string_lossy();

            let _pattern = format!("{log_name}.*.gz");
            if let Ok(entries) = fs::read_dir(log_dir) {
                let mut rotated_files: Vec<PathBuf> = entries
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        let file_name = entry.file_name().to_string_lossy().to_string();
                        file_name.starts_with(&*log_name)
                            && (file_name.contains(".") || file_name.ends_with(".gz"))
                    })
                    .map(|entry| entry.path())
                    .collect();

                // Sort by modification time, oldest first
                rotated_files.sort_by(|a, b| {
                    let a_modified = fs::metadata(a)
                        .and_then(|m| m.modified())
                        .unwrap_or(SystemTime::UNIX_EPOCH);
                    let b_modified = fs::metadata(b)
                        .and_then(|m| m.modified())
                        .unwrap_or(SystemTime::UNIX_EPOCH);
                    a_modified.cmp(&b_modified)
                });

                // Remove oldest files if we have more than rotation_count
                while rotated_files.len() >= inner.rotation_count {
                    if let Some(oldest) = rotated_files.first() {
                        if let Err(e) = fs::remove_file(oldest) {
                            error!("Failed to remove old log file {}: {}", oldest.display(), e);
                        } else {
                            debug!("Removed old log file: {}", oldest.display());
                        }
                        rotated_files.remove(0);
                    }
                }
            }
        }

        // Generate timestamp for the rotated log file
        let now = SystemTime::now();
        let timestamp = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        // Create the new filename with timestamp
        let new_filename = format!("{log_path_str}.{timestamp}");
        let new_path = PathBuf::from(&new_filename);

        // Rename the current log file
        if fs::rename(log_path, &new_path).is_err() {
            error!(
                "Failed to rename log file from {log_path_str} to {new_filename}"
            );
            // Try to reopen the original file
            match OpenOptions::new().create(true).append(true).open(log_path) {
                Ok(file) => {
                    inner.file = Some(file);
                    inner.current_size = 0;
                }
                Err(e) => {
                    error!("Failed to reopen log file {log_path_str}: {e}");
                }
            }
            return Ok(());
        }

        // Compress the rotated file if compression is enabled
        if inner.compression {
            debug!("Compressing rotated log file: {new_filename}");
            // Use gzip for compression if available
            let gzip_output = Command::new("gzip").arg(&new_filename).output();

            match gzip_output {
                Ok(output) => {
                    if !output.status.success() {
                        error!(
                            "Failed to compress log file: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                    } else {
                        debug!("Successfully compressed log file to {new_filename}.gz");
                    }
                }
                Err(e) => {
                    error!("Failed to run gzip: {e}");
                }
            }
        }

        // Create a new log file
        match OpenOptions::new().create(true).append(true).open(log_path) {
            Ok(file) => {
                inner.file = Some(file);
                inner.current_size = 0;
                inner.last_rotation_time = now;
                debug!("Rotated log file: created new file at {log_path_str}");
            }
            Err(e) => {
                error!("Failed to create new log file after rotation: {e}");
            }
        }

        Ok(())
    }

    /// Create a new QueryLogger
    pub fn new(
        log_file_path: Option<String>,
        include_timestamp: bool,
        include_client_addr: bool,
        include_query_type: bool,
        include_query_class: bool,
        rotation_size: usize,
        rotation_interval: String,
        rotation_count: usize,
        compression: bool,
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

        // Get current file size if it exists
        let current_size = if let Some(ref file) = file {
            match file.metadata() {
                Ok(metadata) => metadata.len() as usize,
                Err(_) => 0,
            }
        } else {
            0
        };

        Self {
            inner: Arc::new(Mutex::new(QueryLoggerInner {
                file,
                log_file_path: log_file_path.map(PathBuf::from),
                include_timestamp,
                include_client_addr,
                include_query_type,
                include_query_class,
                rotation_size,
                rotation_interval,
                rotation_count,
                compression,
                last_rotation_time: SystemTime::now(),
                current_size,
            })),
        }
    }

    /// Log a DNS query
    pub async fn log_query(&self, key: &DNSKey, client_addr: &str) {
        // Check if we need to rotate logs
        if let Err(e) = self.check_rotation().await {
            error!("Error checking log rotation: {e}");
        }

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

        // Add client address if enabled (IP only, without port)
        if include_client_addr {
            // Extract just the IP address part without the port
            let client_ip = if let Ok(socket_addr) = client_addr.parse::<std::net::SocketAddr>() {
                socket_addr.ip().to_string()
            } else {
                // Fallback if parsing fails
                client_addr.to_string()
            };
            log_line.push_str(&format!("{client_ip} "));
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
            } else {
                // Update current size for log rotation tracking
                inner.current_size += log_line.len();
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
