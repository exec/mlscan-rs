// Simple port scanner to find open ports quickly
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use futures::future::join_all;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: portscan <ip> [start_port] [end_port]");
        return Ok(());
    }
    
    let ip: IpAddr = args[1].parse()?;
    let start_port: u16 = args.get(2).map(|s| s.parse().unwrap_or(1)).unwrap_or(1);
    let end_port: u16 = args.get(3).map(|s| s.parse().unwrap_or(1000)).unwrap_or(1000);
    
    println!("🔍 Scanning {}:{}-{}", ip, start_port, end_port);
    
    let mut tasks = Vec::new();
    
    for port in start_port..=end_port {
        let task = tokio::spawn(async move {
            if test_port(ip, port).await {
                Some(port)
            } else {
                None
            }
        });
        tasks.push(task);
    }
    
    let results = join_all(tasks).await;
    let mut open_ports: Vec<u16> = results
        .into_iter()
        .filter_map(|result| result.ok().flatten())
        .collect();
    
    open_ports.sort();
    
    if open_ports.is_empty() {
        println!("No open ports found in range {}-{}", start_port, end_port);
    } else {
        println!("\n🎯 Open ports: {:?}", open_ports);
        
        // Test the first few open ports with our probe tool
        for port in open_ports.iter().take(5) {
            println!("\n{}", "=".repeat(50));
            println!("Testing port {}", port);
            println!("{}", "=".repeat(50));
            
            let _ = tokio::process::Command::new("./target/release/mlscan-probe")
                .arg(format!("{}", ip))
                .arg(format!("{}", port))
                .status()
                .await;
        }
    }
    
    Ok(())
}

async fn test_port(ip: IpAddr, port: u16) -> bool {
    let addr = SocketAddr::new(ip, port);
    match timeout(Duration::from_millis(1000), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}