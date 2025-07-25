# MLScan-RS 🧠

Machine learning-enhanced port scanner with adaptive performance that outpaces RustScan.

## 🚀 Features

- **🧠 ML-Powered**: Real adaptive learning (not fake like RustScan's ulimit checking)
- **⚡ Massively Parallel**: True concurrent host scanning - scan 100+ hosts simultaneously  
- **🔍 Service Detection**: Comprehensive service identification with version detection
- **📊 Smart Intelligence**: Actual response time measurement and network classification
- **🔒 Multiple Scan Types**: TCP SYN/Connect/FIN/XMAS/NULL scans, UDP with service probes
- **🌐 Network Discovery**: CIDR ranges, IP ranges, hostname resolution
- **📋 Multiple Output Formats**: Human-readable, JSON, XML (Nmap compatible), CSV
- **🎨 Cyberpunk Theme**: Beautiful terminal output with truecolor support

## 📦 Installation

### Homebrew (macOS/Linux) - Recommended
```bash
brew tap exec/mlscan
brew install mlscan
```

### Direct Download
```bash
# Linux x86_64
wget https://github.com/exec/mlscan-rs/releases/latest/download/mlscan-linux-x86_64.tar.gz
tar -xzf mlscan-linux-x86_64.tar.gz
sudo mv mlscan /usr/local/bin/

# macOS Universal Binary (.pkg installer)
wget https://github.com/exec/mlscan-rs/releases/latest/download/mlscan-macos-universal.pkg
sudo installer -pkg mlscan-macos-universal.pkg -target /
```

### From Source
```bash
cargo build --release
sudo ./install.sh
```

## 🎯 Usage Examples

### Basic Scanning
```bash
# Scan common ports
mlscan --target 192.168.1.1 --ports common

# Scan specific ports  
mlscan --target example.com --ports 22,80,443

# Network scanning
mlscan --target 192.168.1.0/24 --ports web
```

### Advanced Options
```bash
# SYN scan (requires root)
sudo mlscan --target 192.168.1.1 --scan-type syn --ports common

# JSON output with service detection
mlscan --target 8.8.8.8 --ports 53,443 --output-format json

# Lightning-fast LAN scanning (scan 100 hosts concurrently!)
mlscan --target 192.168.1.0/24 --ports 1-65535 --parallel-hosts 100 --timeout 25 --rate-limit 0
```

## ⚡ Performance Advantages

**vs RustScan:**
- **Real ML**: Adaptive learning vs their fake "adaptive" ulimit checking
- **Service Detection**: We identify services + versions, they show port status only
- **True Parallelism**: Concurrent host scanning, not just concurrent ports
- **Smart Timeouts**: ML-optimized based on network characteristics

**Network Scanning Benchmarks:**
```bash
# Scan entire /24 network with all ports - massively parallel
mlscan -t 192.168.1.0/24 -p 1-65535 --parallel-hosts 100

# Smart discovery - find live hosts first, then detailed scan
mlscan -t 192.168.1.0/24 -p common  # Quick discovery
mlscan -t <discovered_hosts> -p 1-65535  # Full scan on live targets
```

## 🔧 Command Line Options

- `-t, --target`: Target IP, hostname, IP range, or CIDR
- `-p, --ports`: Ports to scan (common, web, mail, db, 1-1000, etc.)
- `-T, --scan-type`: syn, connect, udp, fin, xmas, null
- `--timeout`: Timeout per port in milliseconds
- `--rate-limit`: Rate limiting between packets
- `--output-format`: human, json, xml, csv

## 🔒 Security Notice

This tool is for authorized security testing only. Use responsibly and only on networks you own or have explicit permission to test.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.