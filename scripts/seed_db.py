import sys
from pathlib import Path
import random
from datetime import datetime, timedelta

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

from database.db_manager import DatabaseManager

def seed_sample_data():
    db = DatabaseManager()
    print("[*] Seeding database with realistic SOC intrusion and threat records...")

    sample_attacks = [
        {"src": "185.220.101.5", "dst": "192.168.1.100", "dport": 80, "proto": "TCP", "type": "DoS", "conf": 0.98, "threat": 88, "sev": "Critical", "detail": "SYN Flood DoS attack vector exceeding 300 pps"},
        {"src": "45.142.214.12", "dst": "192.168.1.100", "dport": 22, "proto": "TCP", "type": "PortScan", "conf": 0.94, "threat": 75, "sev": "High", "detail": "Nmap stealth SYN scan sweeping ports 20-1024"},
        {"src": "194.26.29.112", "dst": "192.168.1.105", "dport": 445, "proto": "TCP", "type": "Probe", "conf": 0.91, "threat": 68, "sev": "High", "detail": "SMBv1/v2 EternalBlue exploit probe signature"},
        {"src": "185.191.171.18", "dst": "192.168.1.100", "dport": 8080, "proto": "TCP", "type": "DoS", "conf": 0.96, "threat": 82, "sev": "Critical", "detail": "HTTP Slowloris connection exhaustion attempt"},
        {"src": "198.235.24.8", "dst": "192.168.1.102", "dport": 3389, "proto": "TCP", "type": "PortScan", "conf": 0.89, "threat": 45, "sev": "Medium", "detail": "RDP automated port exposure reconnaissance"},
        {"src": "89.248.163.64", "dst": "192.168.1.100", "dport": 53, "proto": "UDP", "type": "DoS", "conf": 0.92, "threat": 90, "sev": "Critical", "detail": "DNS amplification DoS traffic reflection"},
        {"src": "193.32.162.24", "dst": "192.168.1.110", "dport": 21, "proto": "TCP", "type": "Probe", "conf": 0.87, "threat": 35, "sev": "Medium", "detail": "FTP Anonymous brute-force probe detected"}
    ]

    for item in sample_attacks:
        db.insert_alert(
            source_ip=item["src"],
            dest_ip=item["dst"],
            source_port=random.randint(40000, 65000),
            dest_port=item["dport"],
            protocol=item["proto"],
            attack_type=item["type"],
            confidence=item["conf"],
            threat_score=item["threat"],
            severity=item["sev"],
            details=item["detail"]
        )
        
        # Cache threat intel
        db.cache_threat_info(
            ip_address=item["src"],
            threat_score=item["threat"],
            total_reports=random.randint(15, 120),
            is_whitelisted=0,
            country_code="RU" if "185" in item["src"] else "CN",
            isp="Known Cyber Threat / Scanner Hosting"
        )

    # Seed 20 benign network logs
    normal_services = [(80, "TCP"), (443, "TCP"), (53, "UDP")]
    for _ in range(25):
        dport, proto = random.choice(normal_services)
        db.insert_log(
            source_ip=f"192.168.1.{random.randint(10, 50)}",
            dest_ip=f"142.250.190.{random.randint(1, 254)}",
            source_port=random.randint(50000, 60000),
            dest_port=dport,
            protocol=proto,
            packet_length=random.randint(64, 1500),
            tcp_flags="SF" if proto == "TCP" else "",
            is_anomaly=0
        )

    print("[+] Successfully seeded alerts, threat caches, and normal network traffic logs!")

if __name__ == "__main__":
    seed_sample_data()
