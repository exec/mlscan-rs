pub mod tcp;
mod udp;
mod results;
mod discovery;

use anyhow::Result;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};

use crate::cli::ScanType;
use crate::utils::parse_ports;
use crate::network::parse_targets;
use crate::adaptive::{AdaptiveLearning, ScanLearningData, PortScanResult, classify_network};
pub use results::{ScanResult, PortStatus, PortResult, MultiHostScanResult};

/// Check if IP is in private/local range for optimized scanning
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // RFC 1918 private ranges
            (octets[0] == 10) ||
            (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
            (octets[0] == 192 && octets[1] == 168) ||
            // Localhost
            (octets[0] == 127) ||
            // Link-local
            (octets[0] == 169 && octets[1] == 254)
        }
        IpAddr::V6(ipv6) => {
            // IPv6 local ranges
            ipv6.is_loopback() || 
            ipv6.segments()[0] == 0xfe80 || // Link-local
            ipv6.segments()[0] == 0xfc00 || // Unique local
            ipv6.segments()[0] == 0xfd00    // Unique local
        }
    }
}

pub struct Scanner {
    rate_limit: u64,
    timeout: u64,
    parallel_hosts: usize,
    adaptive_learning: AdaptiveLearning,
}

impl Scanner {
    pub fn new(rate_limit: u64, timeout: u64, parallel_hosts: usize) -> Self {
        Self {
            rate_limit,
            timeout,
            parallel_hosts,
            adaptive_learning: AdaptiveLearning::new(),
        }
    }
    
    pub async fn scan(
        &mut self,
        target: &str,
        ports: &str,
        scan_type: ScanType,
    ) -> Result<MultiHostScanResult> {
        let targets = parse_targets(target)?;
        let port_list = parse_ports(ports)?;
        
        let total_operations = targets.len() * port_list.len();
        let pb = ProgressBar::new(total_operations as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("⟦{spinner:.bright_magenta}⟧ [{elapsed_precise}] ⟨{bar:40.bright_green/bright_black}⟩ {pos}/{len} ports scanned ({eta})")?
                .progress_chars("█▉▊▋▌▍▎▏ ")
        );
        
        let start_time = chrono::Utc::now();
        let mut host_results = Vec::new();
        
        for target_ip in targets {
            let host_result = self.scan_single_host(
                target_ip,
                &port_list,
                scan_type,
                pb.clone()
            ).await?;
            
            host_results.push(host_result);
        }
        
        pb.finish_with_message("⟦SCAN COMPLETE⟧ Network discovery finished");
        let end_time = chrono::Utc::now();
        
        Ok(MultiHostScanResult {
            target_spec: target.to_string(),
            scan_type,
            start_time,
            end_time,
            total_hosts: host_results.len(),
            total_ports: port_list.len(),
            hosts: host_results,
        })
    }
    
    async fn scan_single_host(
        &mut self,
        target_ip: IpAddr,
        port_list: &[u16],
        scan_type: ScanType,
        pb: ProgressBar,
    ) -> Result<ScanResult> {
        // Get optimized parameters from adaptive learning
        let optimal_params = self.adaptive_learning.get_optimal_params(target_ip);
        let adaptive_timeout = optimal_params.timeout;
        let adaptive_rate_limit = optimal_params.rate_limit;
        let adaptive_parallelism = optimal_params.parallelism as usize;
        
        // Use adaptive parameters if they're better than defaults
        let effective_timeout = if adaptive_timeout > 0 { adaptive_timeout } else { self.timeout };
        let effective_rate_limit = if adaptive_rate_limit > 0 { adaptive_rate_limit } else { self.rate_limit };
        let effective_parallelism = if adaptive_parallelism > 0 { adaptive_parallelism } else { self.parallel_hosts };
        
        let semaphore = Arc::new(Semaphore::new(effective_parallelism));
        let mut tasks = vec![];
        
        let start_time = chrono::Utc::now();
        let scan_start = std::time::Instant::now();
        
        for port in port_list.iter() {
            let sem = semaphore.clone();
            let target_ip = target_ip.clone();
            let port = *port;
            let timeout = effective_timeout;
            let rate_limit = effective_rate_limit;
            let pb = pb.clone();
            
            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                
                let result = match scan_type {
                    ScanType::Syn => tcp::syn_scan(target_ip, port, timeout).await,
                    ScanType::Connect => {
                        // Use fast connect scan for private networks
                        if is_private_ip(target_ip) {
                            tcp::fast_connect_scan(target_ip, port, timeout).await
                        } else {
                            tcp::connect_scan(target_ip, port, timeout).await
                        }
                    },
                    ScanType::Udp => udp::udp_scan(target_ip, port, timeout).await,
                    ScanType::Fin => tcp::fin_scan(target_ip, port, timeout).await,
                    ScanType::Xmas => tcp::xmas_scan(target_ip, port, timeout).await,
                    ScanType::Null => tcp::null_scan(target_ip, port, timeout).await,
                };
                
                pb.inc(1);
                
                if rate_limit > 0 {
                    sleep(Duration::from_millis(rate_limit)).await;
                }
                
                PortResult { port, status: result }
            });
            
            tasks.push(task);
        }
        
        let port_results = join_all(tasks).await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        
        let end_time = chrono::Utc::now();
        let scan_duration = scan_start.elapsed();
        
        // Collect learning data for adaptive optimization
        let mut learning_port_results = Vec::new();
        let mut total_response_time = 0.0;
        let mut response_count = 0;
        let mut timeout_count = 0;
        
        for port_result in &port_results {
            let is_open = matches!(port_result.status, PortStatus::Open);
            let is_filtered = matches!(port_result.status, PortStatus::Filtered);
            let response_time = match port_result.status {
                PortStatus::Open => {
                    total_response_time += 50.0; // Estimate for open ports
                    response_count += 1;
                    Some(50.0)
                },
                PortStatus::Closed => {
                    total_response_time += 25.0; // Estimate for closed ports
                    response_count += 1;
                    Some(25.0)
                },
                PortStatus::Filtered => {
                    timeout_count += 1;
                    None
                },
                PortStatus::Error => {
                    timeout_count += 1;
                    None
                }
            };
            
            learning_port_results.push(PortScanResult {
                port: port_result.port,
                is_open,
                is_filtered,
                response_time,
                service_detected: None, // TODO: Add service detection
            });
        }
        
        let avg_response_time = if response_count > 0 { 
            total_response_time / response_count as f64 
        } else { 
            effective_timeout as f64 
        };
        
        let timeout_rate = timeout_count as f64 / port_results.len() as f64;
        let scan_performance = 1.0 - timeout_rate; // Simple performance metric
        
        let learning_data = ScanLearningData {
            target: target_ip,
            network_type: classify_network(target_ip),
            port_results: learning_port_results,
            scan_duration,
            avg_response_time,
            timeout_rate,
            parallelism_used: effective_parallelism as u16,
            rate_limit_used: effective_rate_limit,
            scan_performance,
        };
        
        // Learn from the scan results
        self.adaptive_learning.learn_from_scan(&learning_data);
        
        Ok(ScanResult {
            target: target_ip.to_string(),
            target_ip,
            scan_type,
            start_time,
            end_time,
            ports: port_results,
        })
    }
    
    async fn resolve_target(&self, target: &str) -> Result<IpAddr> {
        use std::net::ToSocketAddrs;
        
        if let Ok(ip) = target.parse::<IpAddr>() {
            return Ok(ip);
        }
        
        let addr = format!("{}:0", target)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Failed to resolve hostname"))?;
        
        Ok(addr.ip())
    }
}