use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "portscan")]
#[command(author = "Modern Port Scanner")]
#[command(version = "0.1.0")]
#[command(about = "High-performance, secure port scanner with modern features", long_about = None)]
pub struct Cli {
    #[arg(short, long, help = "Target IP, hostname, IP range (IP1-IP2), or CIDR (192.168.1.0/24). Can be specified multiple times.")]
    pub target: Vec<String>,
    
    #[arg(short, long, default_value = "common", help = "Ports to scan (e.g., 80, 1-1000, 80,443,8080, top100, common, web, mail, db). Can be specified multiple times.")]
    pub ports: Vec<String>,
    
    #[arg(short = 'T', long, value_enum, default_value = "syn", help = "Scan type")]
    pub scan_type: ScanType,
    
    #[arg(short, long, default_value = "100", help = "Rate limit in milliseconds between packets")]
    pub rate_limit: u64,
    
    #[arg(long, default_value = "1000", help = "Timeout in milliseconds for each port")]
    pub timeout: u64,
    
    #[arg(long, default_value = "10", help = "Number of parallel host scans")]
    pub parallel_hosts: usize,
    
    #[arg(short = 'o', long, value_enum, default_value = "human", help = "Output format")]
    pub output_format: OutputFormat,
    
    #[arg(short = 'f', long, help = "Output file path")]
    pub output_file: Option<PathBuf>,
    
    #[arg(long, help = "Disable colored output")]
    pub no_color: bool,
    
    #[arg(short, long, help = "Enable verbose output")]
    pub verbose: bool,

    #[arg(long, help = "Skip host discovery - scan all targets")]
    pub skip_ping: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum ScanType {
    #[value(name = "syn", help = "TCP SYN scan (requires root)")]
    Syn,
    #[value(name = "connect", help = "TCP connect scan")]
    Connect,
    #[value(name = "udp", help = "UDP scan")]
    Udp,
    #[value(name = "fin", help = "TCP FIN scan")]
    Fin,
    #[value(name = "xmas", help = "TCP Xmas scan")]
    Xmas,
    #[value(name = "null", help = "TCP NULL scan")]
    Null,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Syn => write!(f, "SYN"),
            ScanType::Connect => write!(f, "CONNECT"),
            ScanType::Udp => write!(f, "UDP"),
            ScanType::Fin => write!(f, "FIN"),
            ScanType::Xmas => write!(f, "XMAS"),
            ScanType::Null => write!(f, "NULL"),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum OutputFormat {
    #[value(name = "human", help = "Human-readable output")]
    Human,
    #[value(name = "json", help = "JSON output")]
    Json,
    #[value(name = "xml", help = "XML output (Nmap compatible)")]
    Xml,
    #[value(name = "csv", help = "CSV output")]
    Csv,
}