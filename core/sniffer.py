import time
import threading
from pathlib import Path
import sys

# Scapy imports
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

import config
from database.db_manager import DatabaseManager
from core.feature_extractor import FlowFeatureExtractor
from core.detector import IntrusionDetector
from core.threat_intel import ThreatIntelligence

class NetworkSniffer:
    def __init__(self, db_manager=None, alert_callback=None):
        self.db = db_manager or DatabaseManager()
        self.feature_extractor = FlowFeatureExtractor()
        self.detector = IntrusionDetector()
        self.threat_intel = ThreatIntelligence(self.db)
        
        self.alert_callback = alert_callback
        self.is_running = False
        self._thread = None
        self.packet_count = 0
        self.alerts_count = 0

    def parse_packet(self, packet):
        """Extracts low-level protocol details from a Scapy packet."""
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        length = len(packet)
        timestamp = float(packet.time) if hasattr(packet, "time") else time.time()

        protocol = "IP"
        src_port = 0
        dst_port = 0
        flags = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = str(tcp_layer.flags)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": length,
            "flags": flags,
            "timestamp": timestamp
        }

    def process_packet(self, packet):
        """Analyzes each captured packet through the AI detection pipeline."""
        try:
            pkt_data = self.parse_packet(packet)
            if not pkt_data:
                return

            self.packet_count += 1
            
            # 1. Feature Extraction
            features = self.feature_extractor.extract_features(pkt_data)
            
            # 2. Threat Intel Pre-check (cache or simulation)
            threat_data = self.threat_intel.lookup_ip(pkt_data["src_ip"])
            threat_score = threat_data.get("threat_score", 0)

            # 3. ML Inference
            pred = self.detector.predict(features, threat_score=threat_score)
            is_anomaly = 1 if pred["is_attack"] else 0

            # 4. Save to network logs (sample 1 in 5 normal packets to avoid DB bloat, log all attacks)
            if is_anomaly or (self.packet_count % 5 == 0):
                self.db.insert_log(
                    source_ip=pkt_data["src_ip"],
                    dest_ip=pkt_data["dst_ip"],
                    source_port=pkt_data["src_port"],
                    dest_port=pkt_data["dst_port"],
                    protocol=pkt_data["protocol"],
                    packet_length=pkt_data["length"],
                    tcp_flags=pkt_data["flags"],
                    is_anomaly=is_anomaly
                )

            # 5. Handle Alert if Attack Detected
            if pred["is_attack"]:
                self.alerts_count += 1
                details_text = f"Detected {pred['attack_type']} attack with {pred['confidence']*100:.1f}% confidence. Threat Score: {threat_score}"
                
                alert_id = self.db.insert_alert(
                    source_ip=pkt_data["src_ip"],
                    dest_ip=pkt_data["dst_ip"],
                    source_port=pkt_data["src_port"],
                    dest_port=pkt_data["dst_port"],
                    protocol=pkt_data["protocol"],
                    attack_type=pred["attack_type"],
                    confidence=pred["confidence"],
                    threat_score=threat_score,
                    severity=pred["severity"],
                    details=details_text
                )

                if self.alert_callback:
                    alert_payload = {
                        "id": alert_id,
                        "source_ip": pkt_data["src_ip"],
                        "dest_ip": pkt_data["dst_ip"],
                        "attack_type": pred["attack_type"],
                        "severity": pred["severity"],
                        "confidence": pred["confidence"],
                        "threat_score": threat_score,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    self.alert_callback(alert_payload)

        except Exception as e:
            # Prevent crashing the sniffer thread on malformed packets
            pass

    def start_live_capture(self, interface=None, count=0):
        """Starts live packet capture in a background daemon thread."""
        if self.is_running:
            print("[!] Sniffer is already running.")
            return

        self.is_running = True
        target_iface = interface or config.DEFAULT_INTERFACE

        def _sniff_worker():
            print(f"[*] Started live network sniffing on interface: {target_iface or 'Default'}")
            try:
                sniff(
                    iface=target_iface,
                    prn=self.process_packet,
                    stop_filter=lambda x: not self.is_running,
                    count=count,
                    store=False
                )
            except Exception as ex:
                print(f"[!] Sniffing stopped or encountered error: {ex}")
            finally:
                self.is_running = False
                print("[*] Sniffer stopped.")

        self._thread = threading.Thread(target=_sniff_worker, daemon=True)
        self._thread.start()

    def stop_live_capture(self):
        """Stops live capture thread."""
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        print("[*] Sniffer successfully requested to stop.")

    def process_pcap_file(self, pcap_path):
        """
        Processes a saved PCAP file and returns a summary analysis report.
        Extremely useful for viva demos.
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            return {"status": "error", "message": "File does not exist."}

        print(f"[*] Reading PCAP file: {pcap_path}")
        packets = rdpcap(str(pcap_path))
        initial_alerts = self.alerts_count
        pcap_total = len(packets)

        for pkt in packets:
            self.process_packet(pkt)

        detected_in_pcap = self.alerts_count - initial_alerts

        return {
            "status": "success",
            "file_name": pcap_path.name,
            "total_packets": pcap_total,
            "intrusions_detected": detected_in_pcap,
            "processed_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }

# Global singleton sniffer instance
sniffer_instance = None

def get_sniffer():
    global sniffer_instance
    if sniffer_instance is None:
        sniffer_instance = NetworkSniffer()
    return sniffer_instance

if __name__ == "__main__":
    s = get_sniffer()
    print("[*] Testing live sniffer for 5 seconds...")
    s.start_live_capture()
    time.sleep(5)
    s.stop_live_capture()
    print(f"[+] Total packets captured: {s.packet_count}, Alerts: {s.alerts_count}")
