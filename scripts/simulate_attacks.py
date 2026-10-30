import sys
import time
from pathlib import Path
from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap, send

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

import config

def generate_sample_pcaps():
    """Generates test PCAP files containing DoS and PortScan attacks for viva demo."""
    pcap_dir = config.SAMPLE_PCAPS_DIR
    pcap_dir.mkdir(parents=True, exist_ok=True)
    
    print("[*] Generating test PCAPs in data/sample_pcaps/ ...")

    # 1. Generate DoS SYN Flood PCAP
    dos_packets = []
    target_ip = "192.168.1.100"
    attacker_ip = "185.220.101.5" # Attacker IP with malicious threat score
    
    for i in range(150):
        # High-rate SYN packets to port 80 without payload
        pkt = IP(src=attacker_ip, dst=target_ip) / TCP(sport=1024 + i, dport=80, flags="S", seq=1000 + i)
        dos_packets.append(pkt)

    dos_pcap_path = pcap_dir / "sample_syn_flood_dos.pcap"
    wrpcap(str(dos_pcap_path), dos_packets)
    print(f"[+] Created DoS PCAP: {dos_pcap_path} ({len(dos_packets)} packets)")

    # 2. Generate PortScan PCAP
    scan_packets = []
    scanner_ip = "45.142.214.12"
    for port in range(20, 100):
        # Steal SYN scan across various ports
        pkt = IP(src=scanner_ip, dst=target_ip) / TCP(sport=54321, dport=port, flags="S", seq=5000 + port)
        scan_packets.append(pkt)

    scan_pcap_path = pcap_dir / "sample_portscan.pcap"
    wrpcap(str(scan_pcap_path), scan_packets)
    print(f"[+] Created PortScan PCAP: {scan_pcap_path} ({len(scan_packets)} packets)")

    # 3. Generate Normal Web Traffic PCAP
    normal_packets = []
    user_ip = "192.168.1.15"
    web_ip = "142.250.190.46" # Google IP
    # 3-Way Handshake + HTTP GET
    normal_packets.append(IP(src=user_ip, dst=web_ip) / TCP(sport=49152, dport=80, flags="S", seq=100))
    normal_packets.append(IP(src=web_ip, dst=user_ip) / TCP(sport=80, dport=49152, flags="SA", seq=200, ack=101))
    normal_packets.append(IP(src=user_ip, dst=web_ip) / TCP(sport=49152, dport=80, flags="A", seq=101, ack=201))
    normal_packets.append(IP(src=user_ip, dst=web_ip) / TCP(sport=49152, dport=80, flags="PA", seq=101, ack=201) / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

    normal_pcap_path = pcap_dir / "sample_normal_traffic.pcap"
    wrpcap(str(normal_pcap_path), normal_packets)
    print(f"[+] Created Normal Traffic PCAP: {normal_pcap_path} ({len(normal_packets)} packets)")

    print("\n[+] All sample PCAP files successfully generated! You can upload them in the Web UI forensics tab.")

if __name__ == "__main__":
    generate_sample_pcaps()
