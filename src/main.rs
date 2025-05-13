use anyhow::{Context, Result};
use clap::Parser;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::UdpSocket;

/// Custom error types for the application
#[derive(Error, Debug)]
enum EtchDnsError {
    #[error("Invalid DNS packet size: {0}. Must be between 512 and 65536 bytes")]
    InvalidPacketSize(usize),

    #[error("Failed to parse configuration file: {0}")]
    ConfigParseError(String),

    #[error("Failed to read configuration file: {0}")]
    ConfigReadError(String),
}

/// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about = "A simple DNS echo server")]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,
}

/// Configuration structure for the application
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    /// Addresses to listen on (array of "ip:port" strings)
    #[serde(default = "default_listen_addresses")]
    listen_addresses: Vec<String>,

    /// Maximum length of DNS packet in bytes
    #[serde(default = "default_packet_size")]
    dns_packet_len_max: usize,
}

// Default values for configuration
fn default_listen_addresses() -> Vec<String> {
    vec!["0.0.0.0:10000".to_string()]
}

fn default_packet_size() -> usize {
    4096
}

impl Config {
    /// Load configuration from a TOML file
    fn from_file(path: &PathBuf) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        // Validate the configuration
        config.validate()?;

        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> Result<()> {
        // Check DNS packet size limits
        if self.dns_packet_len_max < 512 || self.dns_packet_len_max >= 65536 {
            return Err(EtchDnsError::InvalidPacketSize(self.dns_packet_len_max).into());
        }

        // Validate each listen address
        for addr_str in &self.listen_addresses {
            addr_str
                .parse::<SocketAddr>()
                .with_context(|| format!("Invalid socket address: {}", addr_str))?;
        }

        Ok(())
    }

    /// Parse the listen addresses into SocketAddr objects
    fn socket_addrs(&self) -> Result<Vec<SocketAddr>> {
        let mut addrs = Vec::new();

        for addr_str in &self.listen_addresses {
            let addr = addr_str
                .parse::<SocketAddr>()
                .with_context(|| format!("Invalid socket address: {}", addr_str))?;
            addrs.push(addr);
        }

        Ok(addrs)
    }
}

/// Process a client query by sending the received data back to the client
async fn process_client_query(socket: Arc<UdpSocket>, data: Vec<u8>, addr: SocketAddr) {
    // Log the received packet
    info!("Received {} bytes from {}", data.len(), addr);

    // Log packet details at debug level
    debug!("Packet content: {:?}", data);
    debug!("Processing query from client {}", addr);

    // Send the packet back to the sender
    match socket.send_to(&data, addr).await {
        Ok(bytes_sent) => {
            info!("Sent {} bytes back to {}", bytes_sent, addr);
            debug!("Response successfully sent to client {}", addr);
        }
        Err(e) => {
            error!("Failed to send response to {}: {}", addr, e);
            debug!("Error details: {:?}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger with DEBUG level as default
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();

    // Parse command line arguments
    let args = Args::parse();
    debug!("Command line arguments: {:?}", args);

    // Load configuration from file
    let config = Config::from_file(&args.config)?;
    info!("Loaded configuration: {:?}", config);

    // Get the socket addresses to bind to
    let socket_addrs = config.socket_addrs()?;

    // Create a vector to store all the sockets
    let mut sockets = Vec::new();

    // Bind to each address
    for socket_addr in &socket_addrs {
        let socket = UdpSocket::bind(socket_addr)
            .await
            .with_context(|| format!("Failed to bind to {}", socket_addr))?;
        info!("Listening on: {}", socket.local_addr()?);

        // Create a shareable socket
        sockets.push(Arc::new(socket));
    }

    // Log the buffer capacity
    debug!(
        "Using buffer capacity of {} bytes for each socket",
        config.dns_packet_len_max
    );

    // Create a vector of tasks for each socket
    let mut tasks = Vec::new();

    // Create a task for each socket
    for (i, socket) in sockets.iter().enumerate() {
        let socket = socket.clone();
        let socket_addr = socket_addrs[i];

        // Create a task for this socket
        let task = tokio::spawn(async move {
            // Create a buffer for this task
            let mut buf = vec![0u8; config.dns_packet_len_max];

            // Main receive loop for this socket
            loop {
                // Log that we're waiting for a packet
                debug!("Waiting for incoming UDP packets on {}...", socket_addr);

                // Wait for a packet
                match socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        debug!("Received packet of size {} bytes from {}", len, addr);

                        // Clone the data for the task
                        let data = buf[..len].to_vec();
                        debug!("Cloned packet data for processing");

                        // Clone the socket for the task
                        let socket_clone = socket.clone();
                        debug!("Spawning new task to handle client {}", addr);

                        // Spawn a new task to handle the response
                        tokio::spawn(async move {
                            debug!("Started processing task for client {}", addr);
                            process_client_query(socket_clone, data, addr).await;
                            debug!("Completed processing task for client {}", addr);
                        });
                    }
                    Err(e) => {
                        error!("Failed to receive packet on {}: {}", socket_addr, e);
                    }
                }
            }
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete (which they never will)
    for task in tasks {
        task.await?;
    }

    Ok(())
}
