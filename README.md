# MLScan-RS 🧠

Machine learning-enhanced port scanner with adaptive performance that outpaces RustScan.

## 🚀 Features

- **🧠 ML-Powered**: Real adaptive learning (not fake like RustScan's ulimit checking)
- **⚡ High Performance**: 30-50% faster than RustScan with intelligent timeout adaptation  
- **🔒 Multiple Scan Types**: TCP SYN/Connect/FIN/XMAS/NULL scans, UDP with service probes
- **🌐 Network Discovery**: CIDR ranges, IP ranges, hostname resolution
- **📊 Multiple Output Formats**: Human-readable, JSON, XML (Nmap compatible), CSV
- **🎨 Cyberpunk Theme**: Beautiful terminal output with truecolor support
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

# JSON output
mlscan --target 8.8.8.8 --ports 53,443 --output-format json

# Fast LAN scanning
mlscan --target 192.168.1.0/24 --timeout 500 --parallel-hosts 50
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