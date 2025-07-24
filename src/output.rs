use std::fs::File;
use std::io::{self, Write, BufWriter};
use std::path::PathBuf;
use anyhow::Result;
use colored::*;

use crate::cli::OutputFormat;
use crate::scanner::{MultiHostScanResult, ScanResult, PortStatus};

pub struct OutputWriter {
    format: OutputFormat,
    file: Option<PathBuf>,
}

impl OutputWriter {
    pub fn new(format: OutputFormat, file: Option<PathBuf>) -> Result<Self> {
        Ok(Self { format, file })
    }
    
    pub fn write(&self, result: MultiHostScanResult) -> Result<()> {
        let output = match self.format {
            OutputFormat::Human => self.format_human(result)?,
            OutputFormat::Json => self.format_json(result)?,
            OutputFormat::Xml => self.format_xml(result)?,
            OutputFormat::Csv => self.format_csv(result)?,
        };
        
        match &self.file {
            Some(path) => {
                let file = File::create(path)?;
                let mut writer = BufWriter::new(file);
                writer.write_all(output.as_bytes())?;
                writer.flush()?;
            }
            None => {
                print!("{}", output);
                io::stdout().flush()?;
            }
        }
        
        Ok(())
    }
    
    fn format_human(&self, result: MultiHostScanResult) -> Result<String> {
        let mut output = String::new();
        
        // Cyberpunk ASCII banner with proper alignment
        const BOX_WIDTH: usize = 79;
        
        output.push_str(&format!("\n{}\n", 
            "╔═══════════════════════════════════════════════════════════════════════════════╗".truecolor(0, 212, 255)));
            
        let ascii_lines = vec![
            "  ██▓███   ▒█████   ██▀███  ▄▄▄█████▓  ██████  ▄████▄   ▄▄▄       ███▄    █",
            " ▓██░  ██▒▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █",
            " ▓██░ ██▓▒▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒",
            " ▒██▄█▓▒ ▒▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░   ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒",
            " ▒██▒ ░  ░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░ ▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░",
            " ▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░   ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒"
        ];
        
        for line in ascii_lines {
            let line_len = line.chars().count();
            let padding = if line_len < BOX_WIDTH { BOX_WIDTH - line_len } else { 0 };
            output.push_str(&format!("{}{}{}{}\n",
                "║".truecolor(0, 212, 255),
                line.truecolor(191, 64, 191),
                " ".repeat(padding),
                "║".truecolor(0, 212, 255)));
        }
        
        output.push_str(&format!("{}\n", 
            "╠═══════════════════════════════════════════════════════════════════════════════╣".truecolor(0, 212, 255)));
            
        let complete_text = "░▒ ▒  NETWORK SCAN COMPLETE ▒▒ ░";
        let complete_padding = (BOX_WIDTH - complete_text.len()) / 2;
        let complete_padding_right = BOX_WIDTH - complete_text.len() - complete_padding;
        
        output.push_str(&format!("{}{}{}{}{}\n",
            "║".truecolor(0, 212, 255),
            " ".repeat(complete_padding),
            complete_text.truecolor(0, 255, 65).bold(),
            " ".repeat(complete_padding_right),
            "║".truecolor(0, 212, 255)));
            
        output.push_str(&format!("{}\n", 
            "╚═══════════════════════════════════════════════════════════════════════════════╝".truecolor(0, 212, 255)));
        
        output.push_str(&format!("\n{} {}\n", 
            "⟦TARGET⟧".truecolor(255, 0, 81).bold(),
            result.target_spec.truecolor(255, 255, 255).bold()));
        output.push_str(&format!("{} {}\n", 
            "⟦METHOD⟧".truecolor(255, 140, 0).bold(),
            result.scan_type.to_string().truecolor(255, 255, 255)));
        output.push_str(&format!("{} {}ms\n", 
            "⟦DURATION⟧".truecolor(0, 212, 255).bold(),
            (result.end_time - result.start_time).num_milliseconds().to_string().truecolor(255, 255, 255)));
        output.push_str(&format!("{} {} {}\n", 
            "⟦SCOPE⟧".truecolor(191, 64, 191).bold(),
            result.total_hosts.to_string().truecolor(255, 255, 255),
            "hosts scanned".truecolor(128, 128, 128)));
        output.push_str(&format!("{} {} {}\n\n", 
            "⟦DEPTH⟧".truecolor(191, 64, 191).bold(),
            result.total_ports.to_string().truecolor(255, 255, 255),
            "ports per target".truecolor(128, 128, 128)));
        
        let mut hosts_with_open_ports = 0;
        let mut total_open_ports = 0;
        
        for host in &result.hosts {
            let open_ports: Vec<_> = host.ports.iter()
                .filter(|p| p.status == PortStatus::Open)
                .collect();
            let filtered_ports: Vec<_> = host.ports.iter()
                .filter(|p| p.status == PortStatus::Filtered)
                .collect();
            
            if !open_ports.is_empty() {
                hosts_with_open_ports += 1;
                total_open_ports += open_ports.len();
                
                // Cyberpunk host header with proper alignment
                const HOST_BOX_WIDTH: usize = 77;
                
                output.push_str(&format!("{}\n", 
                    "┌─────────────────────────────────────────────────────────────────────────────┐".truecolor(64, 64, 64)));
                    
                let host_text = format!("⟨HOST⟩ {} ⟨FOUND⟩ {} PORTS", 
                    host.target_ip.to_string(),
                    open_ports.len());
                let host_text_len = host_text.chars().count();
                let host_padding = if host_text_len < HOST_BOX_WIDTH { HOST_BOX_WIDTH - host_text_len } else { 0 };
                
                output.push_str(&format!("│ {}{}{} │\n",
                    format!("⟨HOST⟩ {} ⟨FOUND⟩ {} PORTS", 
                        host.target_ip.to_string().truecolor(255, 255, 255).bold(),
                        open_ports.len().to_string().truecolor(0, 255, 65).bold())
                        .truecolor(0, 212, 255).bold(),
                    " ".repeat(host_padding),
                    "".truecolor(64, 64, 64)));
                    
                output.push_str(&format!("{}\n", 
                    "├─────────────────────────────────────────────────────────────────────────────┤".truecolor(64, 64, 64)));
                
                // Port table header (only print once)
                output.push_str(&format!("│ {:<9} {:<13} {:<54} │\n",
                    "PORT".truecolor(191, 64, 191).bold(),
                    "STATUS".truecolor(191, 64, 191).bold(),
                    "SERVICE".truecolor(191, 64, 191).bold()));
                output.push_str(&format!("│ {:<9} {:<13} {:<54} │\n",
                    "━━━━".truecolor(64, 64, 64),
                    "━━━━━━".truecolor(64, 64, 64),
                    "━━━━━━━".truecolor(64, 64, 64)));
                
                for port in &open_ports {
                    let service = get_service_name(port.port);
                    output.push_str(&format!("│ {:<9} {:<13} {:<54} │\n",
                        port.port.to_string().truecolor(255, 255, 255).bold(),
                        "●OPEN".truecolor(0, 255, 65).bold(),
                        service.truecolor(128, 128, 128)));
                }
                
                if !filtered_ports.is_empty() && filtered_ports.len() <= 5 {
                    let filtered_text = format!("⟨FILTERED⟩ {} ports", filtered_ports.len());
                    let filtered_text_len = filtered_text.chars().count();
                    let filtered_padding = if filtered_text_len < HOST_BOX_WIDTH { HOST_BOX_WIDTH - filtered_text_len } else { 0 };
                    output.push_str(&format!("│ {}{} │\n",
                        filtered_text.truecolor(255, 140, 0),
                        " ".repeat(filtered_padding)));
                        
                    for port in filtered_ports.iter().take(5) {
                        let service = get_service_name(port.port);
                        output.push_str(&format!("│ {:<9} {:<13} {:<54} │\n",
                            port.port.to_string().truecolor(255, 255, 255),
                            "◐FLTRD".truecolor(255, 140, 0),
                            service.truecolor(128, 128, 128)));
                    }
                }
                
                output.push_str(&format!("{}\n\n", 
                    "└─────────────────────────────────────────────────────────────────────────────┘".truecolor(64, 64, 64)));
            }
        }
        
        // Cyberpunk summary with proper alignment
        if hosts_with_open_ports == 0 {
            output.push_str(&format!("{}\n", 
                "╔═══════════════════════════════════════════════════════════════════════════════╗".truecolor(255, 0, 81)));
                
            let no_vuln_text = "⚠ NO OPEN PORTS DETECTED ⚠";
            let no_vuln_padding = (BOX_WIDTH - no_vuln_text.len()) / 2;
            let no_vuln_padding_right = BOX_WIDTH - no_vuln_text.len() - no_vuln_padding;
            output.push_str(&format!("{}{}{}{}{}\n",
                "║".truecolor(255, 0, 81),
                " ".repeat(no_vuln_padding),
                no_vuln_text.truecolor(255, 140, 0).bold(),
                " ".repeat(no_vuln_padding_right),
                "║".truecolor(255, 0, 81)));
                
            let secured_text = "All targets secured and hardened";
            let secured_padding = (BOX_WIDTH - secured_text.len()) / 2;
            let secured_padding_right = BOX_WIDTH - secured_text.len() - secured_padding;
            output.push_str(&format!("{}{}{}{}{}\n",
                "║".truecolor(255, 0, 81),
                " ".repeat(secured_padding),
                secured_text.truecolor(128, 128, 128),
                " ".repeat(secured_padding_right),
                "║".truecolor(255, 0, 81)));
                
            output.push_str(&format!("{}\n", 
                "╚═══════════════════════════════════════════════════════════════════════════════╝".truecolor(255, 0, 81)));
        } else {
            output.push_str(&format!("{}\n", 
                "╔═══════════════════════════════════════════════════════════════════════════════╗".truecolor(0, 255, 65)));
                
            let success_text = "⚡ SCAN SUCCESSFUL ⚡";
            let success_padding = (BOX_WIDTH - success_text.len()) / 2;
            let success_padding_right = BOX_WIDTH - success_text.len() - success_padding;
            output.push_str(&format!("{}{}{}{}{}\n",
                "║".truecolor(0, 255, 65),
                " ".repeat(success_padding),
                success_text.truecolor(0, 255, 65).bold(),
                " ".repeat(success_padding_right),
                "║".truecolor(0, 255, 65)));
                
            let summary_text = format!("Active Hosts: {}  │  Open Ports: {}", 
                hosts_with_open_ports, total_open_ports);
            let summary_padding = (BOX_WIDTH - summary_text.len()) / 2;
            let summary_padding_right = BOX_WIDTH - summary_text.len() - summary_padding;
            output.push_str(&format!("{}{}{}{}{}\n",
                "║".truecolor(0, 255, 65),
                " ".repeat(summary_padding),
                format!("Active Hosts: {}  │  Open Ports: {}", 
                    hosts_with_open_ports.to_string().truecolor(255, 255, 255).bold(),
                    total_open_ports.to_string().truecolor(255, 255, 255).bold()),
                " ".repeat(summary_padding_right),
                "║".truecolor(0, 255, 65)));
                
            output.push_str(&format!("{}\n", 
                "╚═══════════════════════════════════════════════════════════════════════════════╝".truecolor(0, 255, 65)));
        }
        
        output.push_str(&format!("\n{}\n", 
            "▓▒░ SCAN OPERATION COMPLETE ░▒▓".truecolor(191, 64, 191).bold()));
        
        Ok(output)
    }
    
    fn format_json(&self, result: MultiHostScanResult) -> Result<String> {
        Ok(serde_json::to_string_pretty(&result)?)
    }
    
    fn format_xml(&self, result: MultiHostScanResult) -> Result<String> {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<nmaprun>\n");
        xml.push_str(&format!("  <scaninfo type=\"{:?}\" />\n", result.scan_type));
        
        for host in &result.hosts {
            xml.push_str(&format!("  <host><address addr=\"{}\" addrtype=\"ipv4\"/>\n", host.target_ip));
            xml.push_str("    <ports>\n");
            
            for port in &host.ports {
                xml.push_str(&format!(
                    "      <port protocol=\"tcp\" portid=\"{}\">\n",
                    port.port
                ));
                xml.push_str(&format!(
                    "        <state state=\"{}\" reason=\"syn-ack\" reason_ttl=\"0\"/>\n",
                    port.status
                ));
                xml.push_str("      </port>\n");
            }
            
            xml.push_str("    </ports>\n");
            xml.push_str("  </host>\n");
        }
        
        xml.push_str("</nmaprun>\n");
        Ok(xml)
    }
    
    fn format_csv(&self, result: MultiHostScanResult) -> Result<String> {
        let mut csv = String::new();
        csv.push_str("target,target_ip,port,status,scan_type\n");
        
        for host in &result.hosts {
            for port in &host.ports {
                csv.push_str(&format!(
                    "{},{},{},{},{:?}\n",
                    host.target,
                    host.target_ip,
                    port.port,
                    port.status,
                    result.scan_type
                ));
            }
        }
        
        Ok(csv)
    }
}

fn get_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "TELNET",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "RPC",
        139 => "NETBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "ORACLE",
        3306 => "MYSQL",
        3389 => "RDP",
        5000 => "UPNP",
        5432 => "POSTGRESQL",
        5900 => "VNC",
        6379 => "REDIS",
        8080 => "HTTP-ALT",
        8443 => "HTTPS-ALT",
        27017 => "MONGODB",
        _ => "UNKNOWN"
    }
}