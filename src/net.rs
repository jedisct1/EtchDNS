use log::error;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

/// Accepts the next connection, and keeps trying after errors such as running out of file
/// descriptors, which would otherwise stop the server.
pub async fn accept_with_retry(listener: &TcpListener, service: &str) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(connection) => return connection,
            Err(e) => {
                error!("Failed to accept {service} connection: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}
