// Advanced probing tool for service identification
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: mlscan-probe <ip> [port]");
        return Ok(());
    }
    
    let ip: IpAddr = args[1].parse()?;
    let port: u16 = args.get(2).map(|s| s.parse().unwrap_or(80)).unwrap_or(80);
    
    println!("🔍 Advanced probing {}:{}", ip, port);
    
    // Test different probes
    let probes = vec![
        ("HTTP GET", b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()),
        ("HTTP HEAD", b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()),
        ("HTTPS ClientHello", create_tls_client_hello()),
        ("SSH Probe", b"SSH-2.0-OpenSSH_Test\r\n".to_vec()),
        ("Banner Grab", Vec::new()), // Just connect and read
        ("DNS Query", create_dns_query()),
        ("SMTP EHLO", b"EHLO test.local\r\n".to_vec()),
        ("FTP", Vec::new()),
        ("Telnet", b"\r\n".to_vec()),
    ];
    
    for (name, probe) in probes {
        println!("\n📡 Trying {} probe...", name);
        match test_probe(ip, port, &probe).await {
            Ok(Some(response)) => {
                println!("✅ {} Response ({} bytes):", name, response.len());
                let text = String::from_utf8_lossy(&response);
                println!("{}", text.chars().take(300).collect::<String>());
                if text.len() > 300 {
                    println!("... (truncated)");
                }
                
                // Try to identify the service
                let service = identify_service(&response);
                if !service.is_empty() {
                    println!("🎯 Detected service: {}", service);
                }
            }
            Ok(None) => {
                println!("⚪ {} No response", name);
            }
            Err(e) => {
                println!("❌ {} Failed: {}", name, e);
            }
        }
    }
    
    Ok(())
}

async fn test_probe(ip: IpAddr, port: u16, probe: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(Duration::from_secs(3), TcpStream::connect(addr)).await??;
    
    if !probe.is_empty() {
        stream.write_all(probe).await?;
        // Wait a bit for response after sending probe
        tokio::time::sleep(Duration::from_millis(500)).await;
    } else {
        // For banner grabs, wait longer for server to send banner
        tokio::time::sleep(Duration::from_millis(2000)).await;
    }
    
    // Read response
    let mut buffer = vec![0u8; 2048];
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

fn identify_service(response: &[u8]) -> String {
    let text = String::from_utf8_lossy(response).to_lowercase();
    
    // HTTP detection
    if text.starts_with("http/") || text.contains("content-type") || text.contains("server:") {
        if text.contains("apache") {
            return "Apache HTTP Server".to_string();
        } else if text.contains("nginx") {
            return "nginx".to_string();
        } else if text.contains("iis") {
            return "Microsoft IIS".to_string();
        } else {
            return "HTTP Server".to_string();
        }
    }
    
    // SSH detection
    if text.starts_with("ssh-") {
        return "SSH Server".to_string();
    }
    
    // FTP detection
    if text.starts_with("220") && (text.contains("ftp") || text.contains("file transfer")) {
        return "FTP Server".to_string();
    }
    
    // SMTP detection
    if text.starts_with("220") && text.contains("smtp") {
        return "SMTP Server".to_string();
    }
    
    // TLS/SSL detection
    if response.len() > 5 && response[0] == 0x16 && response[1] == 0x03 {
        return "TLS/SSL Server".to_string();
    }
    
    // DNS detection
    if response.len() >= 12 && response[0] == 0x12 && response[1] == 0x34 {
        return "DNS Server".to_string();
    }
    
    // Web admin interfaces
    if text.contains("unauthorized") && text.contains("www-authenticate") {
        return "HTTP Web Admin Interface".to_string();
    }
    
    String::new()
}

fn create_tls_client_hello() -> Vec<u8> {
    // Simplified TLS ClientHello
    vec![
        0x16, 0x03, 0x01, 0x00, 0x2c,  // TLS Record Header
        0x01, 0x00, 0x00, 0x28,        // Handshake Header
        0x03, 0x03,                    // TLS 1.2
        // Random (32 bytes of zeros for simplicity)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,                          // Session ID length
        0x00, 0x02,                    // Cipher suites length
        0x00, 0x35,                    // TLS_RSA_WITH_AES_256_CBC_SHA
        0x01, 0x00                     // Compression methods
    ]
}

fn create_dns_query() -> Vec<u8> {
    // DNS query for google.com A record
    vec![
        0x12, 0x34,             // Transaction ID
        0x01, 0x00,             // Flags (standard query)
        0x00, 0x01,             // Questions: 1
        0x00, 0x00,             // Answer RRs: 0
        0x00, 0x00,             // Authority RRs: 0
        0x00, 0x00,             // Additional RRs: 0
        // Query: google.com
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
        0x03, 0x63, 0x6f, 0x6d,                     // "com"
        0x00,                   // End of name
        0x00, 0x01,             // Type: A
        0x00, 0x01              // Class: IN
    ]
}