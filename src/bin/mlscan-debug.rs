// Debug version of mlscan for testing
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: mlscan-debug <ip> [port]");
        return Ok(());
    }
    
    let ip: IpAddr = args[1].parse()?;
    let port: u16 = args.get(2).map(|s| s.parse().unwrap_or(80)).unwrap_or(80);
    
    println!("Testing connection to {}:{}", ip, port);
    
    match test_port(ip, port).await {
        Ok(Some(response)) => {
            println!("Port {}: OPEN", port);
            println!("Response ({} bytes): {}", response.len(), 
                String::from_utf8_lossy(&response[..response.len().min(200)]));
        }
        Ok(None) => {
            println!("Port {}: OPEN (no response)", port);
        }
        Err(e) => {
            println!("Port {}: CLOSED/FILTERED ({})", port, e);
        }
    }
    
    Ok(())
}

async fn test_port(ip: IpAddr, port: u16) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;
    
    // Send a generic HTTP probe
    let probe = b"GET / HTTP/1.0\r\n\r\n";
    stream.write_all(probe).await?;
    
    // Read response
    let mut buffer = vec![0u8; 1024];
    match timeout(Duration::from_secs(2), stream.read(&mut buffer)).await {
        Ok(Ok(bytes_read)) => {
            buffer.truncate(bytes_read);
            if bytes_read > 0 {
                Ok(Some(buffer))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None)
    }
}