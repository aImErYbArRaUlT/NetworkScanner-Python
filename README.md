# Network Scanner

## Overview
Network Scanner is a Python script designed for network discovery and security testing. It identifies live hosts within a specified subnet by using ARP scanning and then performs a port scan on each discovered host to detect open services on well-known ports.

## Features
- **ARP Scanning**: Quickly detects live hosts on the network.
- **Port Scanning**: Identifies open ports on discovered hosts.
- **Customizable Output**: Allows saving scan results to a specified file.

## Usage Example
Run the script with the required subnet parameter (`-s`) and optional output file (`-f`):
```bash
python network_scanner.py -s 192.168.1.0/24 -f my_network_scan.txt

