import time
from collections import defaultdict
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

class FlowFeatureExtractor:
    """
    Maintains a rolling window of active network connections
    to calculate flow-based statistical features for ML inference.
    """
    def __init__(self, window_size_seconds=5):
        self.window_size = window_size_seconds
        # Key: (src_ip, dst_ip, dst_port, proto)
        self.active_flows = {}
        # Host history tracking: dst_ip -> list of (timestamp, src_ip, dst_port, proto)
        self.host_history = defaultdict(list)
        # Port history tracking: (dst_ip, dst_port) -> list of (timestamp, src_ip)
        self.service_history = defaultdict(list)

    def _determine_service(self, port, protocol):
        """Maps common network ports to service names."""
        port = int(port or 0)
        proto = str(protocol).lower()
        if proto == "icmp":
            return "echo"
        if port in (80, 8080, 8000):
            return "http"
        elif port == 443:
            return "https"
        elif port == 53:
            return "dns"
        elif port in (20, 21):
            return "ftp"
        elif port == 22:
            return "ssh"
        elif port == 23:
            return "telnet"
        elif port == 25:
            return "smtp"
        elif port in (135, 137, 138, 139, 445):
            return "netbios"
        elif port > 1024:
            return "private"
        else:
            return "other"

    def _determine_flag(self, tcp_flags):
        """Translates Scapy TCP flags into NSL-KDD flag equivalents."""
        if not tcp_flags:
            return "SF"
        flags = str(tcp_flags).upper()
        if "S" in flags and "A" not in flags:
            return "S0"  # Connection attempt, no reply seen yet (common in SYN floods)
        elif "R" in flags:
            return "REJ" # Connection rejected
        elif "F" in flags:
            return "SF"  # Normal termination
        return "SF"

    def clean_expired_history(self, current_time):
        """Removes entries older than window_size from rolling history."""
        cutoff = current_time - self.window_size
        for host in list(self.host_history.keys()):
            self.host_history[host] = [e for e in self.host_history[host] if e[0] >= cutoff]
            if not self.host_history[host]:
                del self.host_history[host]

        for srv in list(self.service_history.keys()):
            self.service_history[srv] = [e for e in self.service_history[srv] if e[0] >= cutoff]
            if not self.service_history[srv]:
                del self.service_history[srv]

    def extract_features(self, packet_info):
        """
        Takes raw packet metadata dictionary:
        {
            'src_ip': str,
            'dst_ip': str,
            'src_port': int,
            'dst_port': int,
            'protocol': str,
            'length': int,
            'flags': str,
            'timestamp': float
        }
        Returns a feature dictionary ready for IntrusionDetector.
        """
        now = packet_info.get("timestamp", time.time())
        src_ip = packet_info.get("src_ip", "0.0.0.0")
        dst_ip = packet_info.get("dst_ip", "0.0.0.0")
        src_port = packet_info.get("src_port", 0)
        dst_port = packet_info.get("dst_port", 0)
        proto = packet_info.get("protocol", "TCP").lower()
        length = packet_info.get("length", 64)
        flags = packet_info.get("flags", "")

        self.clean_expired_history(now)

        # Update host & service histories
        self.host_history[dst_ip].append((now, src_ip, dst_port, proto))
        self.service_history[(dst_ip, dst_port)].append((now, src_ip))

        # Calculate traffic count statistics within window
        dst_entries = self.host_history[dst_ip]
        dst_host_count = len(dst_entries)
        
        srv_entries = self.service_history[(dst_ip, dst_port)]
        dst_host_srv_count = len(srv_entries)

        # Connection rates
        same_srv_count = sum(1 for e in dst_entries if e[2] == dst_port)
        same_srv_rate = (same_srv_count / dst_host_count) if dst_host_count > 0 else 1.0
        diff_srv_rate = 1.0 - same_srv_rate

        same_src_port_count = sum(1 for e in dst_entries if e[1] == src_ip)
        same_src_port_rate = (same_src_port_count / dst_host_count) if dst_host_count > 0 else 0.0

        service = self._determine_service(dst_port, proto)
        kdd_flag = self._determine_flag(flags)

        features = {
            "duration": round(float(packet_info.get("duration", 0.05)), 3),
            "protocol_type": proto,
            "service": service,
            "flag": kdd_flag,
            "src_bytes": length if src_ip != "0.0.0.0" else 0,
            "dst_bytes": 0,
            "count": min(dst_host_count, 511),
            "srv_count": min(dst_host_srv_count, 511),
            "same_srv_rate": round(float(same_srv_rate), 3),
            "diff_srv_rate": round(float(diff_srv_rate), 3),
            "dst_host_count": min(dst_host_count, 255),
            "dst_host_srv_count": min(dst_host_srv_count, 255),
            "dst_host_same_srv_rate": round(float(same_srv_rate), 3),
            "dst_host_diff_srv_rate": round(float(diff_srv_rate), 3),
            "dst_host_same_src_port_rate": round(float(same_src_port_rate), 3)
        }

        return features

if __name__ == "__main__":
    extractor = FlowFeatureExtractor()
    sample_pkt = {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "tcp",
        "length": 60,
        "flags": "S",
        "timestamp": time.time()
    }
    extracted = extractor.extract_features(sample_pkt)
    print("Extracted Features:", extracted)
