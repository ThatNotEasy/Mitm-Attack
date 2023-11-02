# Author: Pari Malam

from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw, ICMP
from colorama import Fore, Style, init
import time
from mitmproxy.tools.main import mitmdump
from mitmproxy import http

init(autoreset=True)

def timestamp():
    return time.strftime("%H:%M:%S")

def handle_dns(packet):
    if packet.haslayer(DNS) and packet[DNS].opcode == 0 and packet.haslayer(DNSQR):
        domain = packet[DNSQR].qname.decode('utf-8')
        if DNSRR in packet:
            resolved_ip = packet[DNSRR].rdata
            print(f"{timestamp()} DNS Request: {Fore.GREEN}{domain}{Style.RESET_ALL} -> Resolved IP: {Fore.CYAN}{resolved_ip}{Style.RESET_ALL}")
        else:
            print(f"{timestamp()} DNS Request: {Fore.GREEN}{domain}{Style.RESET_ALL}")

def handle_tcp(packet):
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    source_port = packet[TCP].sport
    destination_port = packet[TCP].dport
    print(f"{timestamp()} TCP Packet: Source IP: {source_ip}:{source_port} -> Destination IP: {destination_ip}:{destination_port}")
    
    if packet.haslayer(Raw) and "HTTP" in str(packet[Raw].load):
        print(f"{timestamp()} Potential HTTP Packet: Source IP: {source_ip}:{source_port} -> Destination IP: {destination_ip}:{destination_port}")

def handle_udp(packet):
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    source_port = packet[UDP].sport
    destination_port = packet[UDP].dport
    print(f"{timestamp()} UDP Packet: Source IP: {source_ip}:{source_port} -> Destination IP: {destination_ip}:{destination_port}")

def handle_icmp(packet):
    print(f"{timestamp()} ICMP Packet: {Fore.YELLOW}{packet[IP].src}{Style.RESET_ALL} -> {Fore.YELLOW}{packet[IP].dst}{Style.RESET_ALL}")

def packet_handler(packet):
    if DNS in packet:
        handle_dns(packet)
    if TCP in packet:
        handle_tcp(packet)
    if UDP in packet:
        handle_udp(packet)
    if ICMP in packet:
        handle_icmp(packet)

network_interface = "Wi-Fi"
sniff(iface=network_interface, prn=packet_handler)

if __name__ == "__main__":
    def request(flow: http.HTTPFlow):
        if flow.request.pretty_url.startswith("https://"):
            print(f"{timestamp()} Intercepted HTTPS request: {Fore.MAGENTA}{flow.request.pretty_url}{Style.RESET_ALL}")

    mitmdump(args=["-s", "myaddon.py", "--set", f"confdir={temp_directory}"])
