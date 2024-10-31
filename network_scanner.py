"""Ensure you adjust paths and other configurations according to your specific environment and requirements. 
This comprehensive setup should provide a robust basis for the educational project, emphasizing both functionality, IMPORTANT!!: and adherence to ethical standards."""

import scapy.all as scapy
import socket
import argparse
import datetime
import os
import threading
from threading import Semaphore

def perform_arp_scan(target_subnet):
    """Perform an ARP scan to identify active hosts on the subnet."""
    try:
        arp_request = scapy.ARP(pdst=target_subnet)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        active_hosts = [element[1].psrc for element in answered_list]
        print(f"Active hosts detected: {active_hosts}")
        return active_hosts
    except Exception as e:
        print(f"Error during ARP scan: {e}")
        return []

def perform_port_scan(host):
    """Scan specified ports on the host to check for open services."""
    well_known_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3389]
    open_ports = {}
    for port in well_known_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports[port] = get_service_by_port(port)
        except Exception as e:
            print(f"Error scanning port {port} on host {host}: {e}")
        finally:
            sock.close()
    return open_ports

def get_service_by_port(port):
    """Map port numbers to common service names."""
    services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        3389: 'RDP'
    }
    return services.get(port, 'Unknown Service')

def log_results(filename, results):
    """Log the scanning results into a specified file."""
    # Set base path (use current working directory if no specific path is provided)
    base_path = os.getcwd()
    full_path = os.path.join(base_path, filename)

    # Write results to the file
    with open(full_path, 'w') as file:  # Use 'w' to overwrite the file on each run
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"Scanning results at {timestamp}\n")

        if not results:
            file.write("No active hosts detected.\n")
        else:
            for host, ports in results.items():
                file.write(f"{host}:\n")
                for port, service in ports.items():
                    file.write(f"  Port {port} ({service}) is open\n")
    
    print(f"Results saved to {full_path}")

def parse_arguments():
    """Parse command-line arguments for subnet and output file."""
    parser = argparse.ArgumentParser(description='Network Scanner Tool')
    parser.add_argument('-s', '--subnet', type=str, required=True, help='Target subnet for ARP scan')
    parser.add_argument('-f', '--file', type=str, default='scan_results.txt', help='File to log the results')
    return parser.parse_args()

def main():
    args = parse_arguments()
    active_hosts = perform_arp_scan(args.subnet)
    all_results = {}
    semaphore = Semaphore(5)  # Limit number of concurrent scans

    threads = []
    for host in active_hosts:
        thread = threading.Thread(target=scan_host, args=(host, all_results, semaphore))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    log_results(args.file, all_results)

def scan_host(host, all_results, semaphore):
    """Scan a single host for open well-known ports."""
    with semaphore:
        open_ports = perform_port_scan(host)
        all_results[host] = open_ports
        print(f"Completed scan for host {host}")

if __name__ == "__main__":
    
    
    main()
    
    """ Ensure you adjust paths and other configurations according to your specific environment and requirements. 
This comprehensive setup should provide a robust basis for the educational project, 
emphasizing both functionality and adherence to ethical standards. """

