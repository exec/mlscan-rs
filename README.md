# PortScan-RS 🔥

A high-performance, secure port scanner with modern features and cyberpunk styling.

## 🚀 Features

- **⚡ High Performance**: Async I/O with configurable parallelism and rate limiting
- **🔒 Multiple Scan Types**: TCP SYN/Connect/FIN/XMAS/NULL scans, UDP with service probes
- **🌐 Network Discovery**: CIDR ranges, IP ranges, hostname resolution
- **📊 Multiple Output Formats**: Human-readable, JSON, XML (Nmap compatible), CSV
- **🎨 Cyberpunk Theme**: Beautiful terminal output with truecolor support
- **⚡ Smart Timeouts**: Optimized scanning for both LAN and WAN networks
- **🔧 Highly Configurable**: Rate limiting, timeouts, parallel scanning options

## 📦 Installation

### Quick Install
```bash
./install.sh
```

### From Source
```bash
cargo build --release
sudo ./install.sh
```

### Using Make
```bash
make install     # Build and install
make uninstall   # Remove
```

## 🎯 Usage Examples

### Basic Scanning
```bash
# Scan common ports
portscan --target 192.168.1.1 --ports common

# Scan specific ports  
portscan --target example.com --ports 22,80,443

# Network scanning
portscan --target 192.168.1.0/24 --ports web
```

### Advanced Options
```bash
# SYN scan (requires root)
sudo portscan --target 192.168.1.1 --scan-type syn --ports common

# JSON output
portscan --target 8.8.8.8 --ports 53,443 --output-format json

# Fast LAN scanning
portscan --target 192.168.1.0/24 --timeout 500 --parallel-hosts 50
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