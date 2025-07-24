use std::net::IpAddr;
use std::time::Duration;
use tokio::time::timeout;

/// Quick ping check to see if host is up before scanning ports
pub async fn is_host_up(target: IpAddr, timeout_ms: u64) -> bool {
    // Try common ports that are likely to respond
    let check_ports = vec![80, 443, 22, 445, 135, 3389];
    let duration = Duration::from_millis(timeout_ms / 2); // Use half timeout for discovery
    
    for port in check_ports {
        let addr = std::net::SocketAddr::new(target, port);
        match timeout(duration, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => return true, // Host is definitely up
            Ok(Err(e)) => {
                // Connection refused means host is up but port is closed
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    return true;
                }
            }
            Err(_) => continue, // Timeout, try next port
        }
    }
    
    // If all ports timeout, host is likely down or heavily filtered
    false
}

/// Simple TCP-based host discovery (no root required)
pub async fn tcp_ping(target: IpAddr, timeout_ms: u64) -> bool {
    is_host_up(target, timeout_ms).await
}