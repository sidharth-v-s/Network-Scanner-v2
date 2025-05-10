# Network Security Scanner

A comprehensive GUI-based cybersecurity toolkit built with Python and DearPyGui, providing essential network reconnaissance and security assessment tools.

![Network Security Scanner](https://raw.githubusercontent.com/sidharth-v-s//Network-Scanner-v2/main/screenshots/main_screen.png)

## Features

### 🔍 Host Lookup
- Scans subnets to discover active hosts
- Identifies device hostnames, MAC addresses, and hardware vendors
- Perfect for network mapping and asset identification

### 🔒 Port Scanner
- Multiple scan types including basic TCP scans, version detection, and OS fingerprinting
- Customizable scan options (SYN stealth scan, UDP scan, comprehensive scan)
- Identifies open ports, running services, and software versions
- OS detection capabilities

### 🌐 Web Subdirectory Scanner
- Discovers hidden directories and files on web servers
- Support for custom wordlists
- Identifies various HTTP response codes (200 OK, redirects, 403 Forbidden, etc.)
- Essential for web application security testing

## Screenshots

![Host Lookup Tool](https://raw.githubusercontent.com/sidharth-v-s//Network-Scanner-v2/main/screenshots/host_lookup.png)
![Port Scanner](https://raw.githubusercontent.com/sidharth-v-s//Network-Scanner-v2/main/screenshots/port_scanner.png)
![Web Directory Scanner](https://raw.githubusercontent.com/sidharth-v-s//Network-Scanner-v2/main/screenshots/web_scanner.png)

## Requirements

- Python 3.6+
- DearPyGui 1.8.0+
- python-nmap 0.7.1+
- requests 2.28.0+

## Installation

1. Clone this repository:
```bash
git clone https://github.com/sidharth-v-s//Network-Scanner-v2.git
cd network-security-scanner
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

### Additional Requirements

- For the Host Lookup and Port Scanner features, you must have Nmap installed on your system
  - [Download Nmap](https://nmap.org/download.html)

- For directory scanning, you'll need a wordlist file
  - [SecLists](https://github.com/danielmiessler/SecLists) is a good resource for wordlists

## Usage

### Host Lookup
1. Enter a subnet in CIDR notation (e.g., 192.168.1.0/24)
2. Click "Scan"
3. View discovered hosts with their MAC addresses and vendor information

### Port Scanner
1. Enter an IP address to scan
2. Select a scan type from the dropdown menu
3. Click "Scan"
4. View open ports, services, versions, and OS detection results

### Web Subdirectory Scanner
1. Enter the base URL (e.g., https://example.com)
2. Click "Browse" to select a wordlist file
3. Click "Scan"
4. View discovered directories and files with their HTTP response codes

## Ethical Usage

This tool is designed for security professionals, network administrators, and ethical hackers to test and secure their own systems and networks. Please use this tool responsibly and only on systems you own or have explicit permission to test.

⚠️ **Warning**: Unauthorized scanning of networks or systems may be illegal in your jurisdiction and is against the terms of service of many organizations. Always get proper authorization before conducting any security testing.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgments

- [DearPyGui](https://github.com/hoffstadt/DearPyGui) for the GUI framework
- [python-nmap](https://github.com/nmap/nmap) for the network scanning capabilities
- All contributors who have helped improve this tool
