import scapy.all as scapy
import nmap
import socket

def get_mac_address(ip_address):
    """Gets the MAC address of a device, given its IP address."""
    arp_request = scapy.ARP(pdst=ip_address)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def get_hostname(ip_address):
    """Attempts to get the hostname of a device, given its IP address."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return None

def scan_network():
    """Scans the network and lists devices."""
    scanner = nmap.PortScanner()
    scanner.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389')  # Adjust IP range if needed

    print("IP Address\t\tMAC Address\t\tHostname")
    for host in scanner.all_hosts():
        ip_address = host
        mac_address = get_mac_address(ip_address)
        hostname = get_hostname(ip_address)
        print(f"{ip_address}\t\t{mac_address}\t\t{hostname}")

if __name__ == "__main__":
    scan_network()
