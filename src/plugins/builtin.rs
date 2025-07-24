use std::net::IpAddr;
use anyhow::Result;
use async_trait::async_trait;

use super::{ScannerPlugin, OutputPlugin, ServiceDetectionPlugin, PluginConfig, ServiceInfo};
use crate::scanner::{PortStatus, MultiHostScanResult};
use crate::cli::ScanType;

/// Built-in TCP Connect scanner plugin
pub struct TcpConnectPlugin {
    name: String,
    version: String,
}

impl TcpConnectPlugin {
    pub fn new() -> Self {
        Self {
            name: "tcp_connect".to_string(),
            version: "1.0.0".to_string(),
        }
    }
}

#[async_trait]
impl ScannerPlugin for TcpConnectPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn version(&self) -> &str {
        &self.version
    }
    
    fn description(&self) -> &str {
        "TCP Connect scan using standard socket connections"
    }
    
    fn supported_scan_types(&self) -> Vec<ScanType> {
        vec![ScanType::Connect]
    }
    
    async fn initialize(&mut self, _config: PluginConfig) -> Result<()> {
        Ok(())
    }
    
    async fn scan_port(&self, target: IpAddr, port: u16, timeout_ms: u64) -> Result<PortStatus> {
        // Use the existing TCP connect scan implementation
        Ok(crate::scanner::tcp::connect_scan(target, port, timeout_ms).await)
    }
}

/// Built-in Human-readable output plugin
pub struct HumanOutputPlugin {
    name: String,
}

impl HumanOutputPlugin {
    pub fn new() -> Self {
        Self {
            name: "human_output".to_string(),
        }
    }
}

#[async_trait]
impl OutputPlugin for HumanOutputPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn file_extension(&self) -> &str {
        "txt"
    }
    
    fn content_type(&self) -> &str {
        "text/plain"
    }
    
    async fn initialize(&mut self, _config: PluginConfig) -> Result<()> {
        Ok(())
    }
    
    async fn format_results(&self, results: &MultiHostScanResult) -> Result<String> {
        // Use the existing human output format
        let mut output = String::new();
        
        output.push_str(&format!("Scan Results for: {}\n", results.target_spec));
        output.push_str(&format!("Scan Type: {:?}\n", results.scan_type));
        output.push_str(&format!("Start Time: {}\n", results.start_time));
        output.push_str(&format!("End Time: {}\n", results.end_time));
        output.push_str(&format!("Total Hosts: {}\n", results.total_hosts));
        output.push_str(&format!("Total Ports: {}\n\n", results.total_ports));
        
        for host_result in &results.hosts {
            output.push_str(&format!("Host: {}\n", host_result.target));
            
            let open_ports: Vec<_> = host_result.ports
                .iter()
                .filter(|p| matches!(p.status, PortStatus::Open))
                .collect();
            
            if open_ports.is_empty() {
                output.push_str("  No open ports found\n\n");
            } else {
                output.push_str("  Open Ports:\n");
                for port_result in open_ports {
                    output.push_str(&format!("    {} - {}\n", port_result.port, "Open"));
                }
                output.push('\n');
            }
        }
        
        Ok(output)
    }
}

/// Built-in JSON output plugin
pub struct JsonOutputPlugin {
    name: String,
}

impl JsonOutputPlugin {
    pub fn new() -> Self {
        Self {
            name: "json_output".to_string(),
        }
    }
}

#[async_trait]
impl OutputPlugin for JsonOutputPlugin {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn file_extension(&self) -> &str {
        "json"
    }
    
    fn content_type(&self) -> &str {
        "application/json"
    }
    
    async fn initialize(&mut self, _config: PluginConfig) -> Result<()> {
        Ok(())
    }
    
    async fn format_results(&self, results: &MultiHostScanResult) -> Result<String> {
        serde_json::to_string_pretty(results).map_err(|e| anyhow::anyhow!(e))
    }
}

/// Built-in HTTP service detection plugin
pub struct HttpServicePlugin {
    name: String,
}

impl HttpServicePlugin {
    pub fn new() -> Self {
        Self {
            name: "http_service".to_string(),
        }
    }
}

#[async_trait]
impl ServiceDetectionPlugin for HttpServicePlugin {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn supported_ports(&self) -> Vec<u16> {
        vec![80, 8080, 8000, 8443, 9000, 3000]
    }
    
    async fn initialize(&mut self, _config: PluginConfig) -> Result<()> {
        Ok(())
    }
    
    async fn detect_service(&self, target: IpAddr, port: u16, timeout_ms: u64) -> Result<Option<ServiceInfo>> {
        use tokio::net::TcpStream;
        use tokio::time::{timeout, Duration};
        use tokio::io::{AsyncWriteExt, AsyncReadExt};
        
        let timeout_duration = Duration::from_millis(timeout_ms);
        
        match timeout(timeout_duration, TcpStream::connect((target, port))).await {
            Ok(Ok(mut stream)) => {
                // Send HTTP GET request
                let request = format!("GET / HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: PortScan-RS/1.0\r\nConnection: close\r\n\r\n", target, port);
                
                if stream.write_all(request.as_bytes()).await.is_ok() {
                    let mut buffer = vec![0; 1024];
                    if let Ok(n) = stream.read(&mut buffer).await {
                        let response = String::from_utf8_lossy(&buffer[..n]);
                        
                        if response.starts_with("HTTP/") {
                            let mut service = ServiceInfo {
                                name: "HTTP".to_string(),
                                version: None,
                                banner: Some(response.lines().next().unwrap_or("").to_string()),
                                confidence: 0.9,
                                additional_info: std::collections::HashMap::new(),
                            };
                            
                            // Try to extract server information
                            for line in response.lines() {
                                if line.to_lowercase().starts_with("server:") {
                                    service.additional_info.insert(
                                        "server".to_string(),
                                        line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string()
                                    );
                                    break;
                                }
                            }
                            
                            return Ok(Some(service));
                        }
                    }
                }
            }
            _ => {}
        }
        
        Ok(None)
    }
}

/// Built-in SSH service detection plugin
pub struct SshServicePlugin {
    name: String,
}

impl SshServicePlugin {
    pub fn new() -> Self {
        Self {
            name: "ssh_service".to_string(),
        }
    }
}

#[async_trait]
impl ServiceDetectionPlugin for SshServicePlugin {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn supported_ports(&self) -> Vec<u16> {
        vec![22, 2222]
    }
    
    async fn initialize(&mut self, _config: PluginConfig) -> Result<()> {
        Ok(())
    }
    
    async fn detect_service(&self, target: IpAddr, port: u16, timeout_ms: u64) -> Result<Option<ServiceInfo>> {
        use tokio::net::TcpStream;
        use tokio::time::{timeout, Duration};
        use tokio::io::AsyncReadExt;
        
        let timeout_duration = Duration::from_millis(timeout_ms);
        
        match timeout(timeout_duration, TcpStream::connect((target, port))).await {
            Ok(Ok(mut stream)) => {
                let mut buffer = vec![0; 256];
                if let Ok(n) = stream.read(&mut buffer).await {
                    let banner = String::from_utf8_lossy(&buffer[..n]);
                    
                    if banner.starts_with("SSH-") {
                        let service = ServiceInfo {
                            name: "SSH".to_string(),
                            version: banner.lines().next()
                                .and_then(|line| line.split_whitespace().nth(0))
                                .map(|v| v.to_string()),
                            banner: Some(banner.lines().next().unwrap_or("").to_string()),
                            confidence: 0.95,
                            additional_info: std::collections::HashMap::new(),
                        };
                        
                        return Ok(Some(service));
                    }
                }
            }
            _ => {}
        }
        
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tcp_connect_plugin_creation() {
        let plugin = TcpConnectPlugin::new();
        assert_eq!(plugin.name(), "tcp_connect");
        assert_eq!(plugin.version(), "1.0.0");
        assert!(plugin.supports_scan_type(ScanType::Connect));
        assert!(!plugin.supports_scan_type(ScanType::Syn));
    }
    
    #[test]
    fn test_output_plugins() {
        let human_plugin = HumanOutputPlugin::new();
        assert_eq!(human_plugin.name(), "human_output");
        assert_eq!(human_plugin.file_extension(), "txt");
        assert_eq!(human_plugin.content_type(), "text/plain");
        
        let json_plugin = JsonOutputPlugin::new();
        assert_eq!(json_plugin.name(), "json_output");
        assert_eq!(json_plugin.file_extension(), "json");
        assert_eq!(json_plugin.content_type(), "application/json");
    }
    
    #[test]
    fn test_service_detection_plugins() {
        let http_plugin = HttpServicePlugin::new();
        assert_eq!(http_plugin.name(), "http_service");
        assert!(http_plugin.supported_ports().contains(&80));
        assert!(http_plugin.supported_ports().contains(&8080));
        
        let ssh_plugin = SshServicePlugin::new();
        assert_eq!(ssh_plugin.name(), "ssh_service");
        assert!(ssh_plugin.supported_ports().contains(&22));
    }
}