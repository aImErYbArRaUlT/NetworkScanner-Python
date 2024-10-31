# Network Scanner

## Custom Input Example
usage: network_scanner.py [-h] -s SUBNET [-f FILE]
python network_scanner.py -s 192.168.1.0/24 -f my_network_scan.txt

## Description
This Python script performs network discovery using ARP scanning to detect live hosts within a specified subnet and then conducts a port scan on well-known ports to determine open services.

## Installation
- Requires Python 3.x
- Dependencies:
  ```bash
  pip install scapy
