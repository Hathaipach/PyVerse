from scapy.all import *

def scan_network(ip_range):
    print(f"Scanning network {ip_range}")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients = []
    for element in answered_list:
        client = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        clients.append(client)

    for client in clients:
        print(f"IP: {client['ip']} MAC: {client['mac']}")

# Example usage 
scan_network("192.168.1.0/24")
