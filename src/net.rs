use log::{debug, error};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

/// Tells whether the client just hung up or vanished.
///
/// Junk traffic does this all the time, so it isn't worth an error message.
pub fn is_peer_gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::TimedOut
    )
}

/// Accepts the next connection, and keeps trying after errors such as running out of file
/// descriptors, which would otherwise stop the server.
pub async fn accept_with_retry(listener: &TcpListener, service: &str) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(connection) => return connection,
            Err(e) if is_peer_gone(&e) => {
                debug!("{service} client went away before its connection was accepted: {e}");
            }
            Err(e) => {
                error!("Failed to accept {service} connection: {e}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn reset_connection_is_peer_gone() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();

        // Hang up abruptly, like scanners do
        client.set_zero_linger().unwrap();
        drop(client);

        let e = server.read_exact(&mut [0u8; 2]).await.unwrap_err();
        assert!(is_peer_gone(&e), "{e:?}");
    }
}
