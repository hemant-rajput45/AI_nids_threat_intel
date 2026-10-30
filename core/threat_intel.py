import requests
import json
import ipaddress
from datetime import datetime, timedelta
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

import config
from database.db_manager import DatabaseManager

class ThreatIntelligence:
    def __init__(self, db_manager=None):
        self.db = db_manager or DatabaseManager()
        self.api_key = config.ABUSEIPDB_API_KEY
        self.api_url = config.ABUSEIPDB_API_URL

    def is_private_ip(self, ip_str):
        """Checks if an IP address is private (RFC 1918) or loopback."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except ValueError:
            return True

    def lookup_ip(self, ip_address):
        """
        Queries threat intelligence for an IP address.
        Checks local cache first to avoid API quotas.
        """
        # Private IPs (LAN traffic like 192.168.x.x, 10.x.x.x, 127.0.0.1) have 0 threat score
        if self.is_private_ip(ip_address):
            return {
                "ip_address": ip_address,
                "threat_score": 0,
                "total_reports": 0,
                "is_whitelisted": 1,
                "country_code": "LOCAL",
                "isp": "Local Area Network / Private IP",
                "cached": True
            }

        # 1. Check local SQLite cache
        cached = self.db.get_cached_threat(ip_address)
        if cached:
            # Check cache age
            try:
                last_checked = datetime.strptime(cached["last_checked"], "%Y-%m-%d %H:%M:%S")
                if datetime.now() - last_checked < timedelta(hours=config.THREAT_CACHE_TTL_HOURS):
                    cached["cached"] = True
                    return cached
            except Exception:
                pass

        # 2. Query AbuseIPDB API if API key is provided
        if self.api_key:
            try:
                headers = {
                    "Accept": "application/json",
                    "Key": self.api_key
                }
                params = {
                    "ipAddress": ip_address,
                    "maxAgeInDays": 90,
                    "verbose": True
                }
                response = requests.get(self.api_url, headers=headers, params=params, timeout=5)
                if response.status_code == 200:
                    data = response.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    total_reports = data.get("totalReports", 0)
                    is_whitelisted = 1 if data.get("isWhitelisted") else 0
                    country = data.get("countryCode", "Unknown")
                    isp = data.get("isp", "Unknown")

                    # Save to cache
                    self.db.cache_threat_info(
                        ip_address=ip_address,
                        threat_score=score,
                        total_reports=total_reports,
                        is_whitelisted=is_whitelisted,
                        country_code=country,
                        isp=isp
                    )
                    return {
                        "ip_address": ip_address,
                        "threat_score": score,
                        "total_reports": total_reports,
                        "is_whitelisted": is_whitelisted,
                        "country_code": country,
                        "isp": isp,
                        "cached": False
                    }
            except Exception as e:
                print(f"[!] Error querying AbuseIPDB for {ip_address}: {e}")

        # 3. Fallback / Offline Known Threat Feed Simulator
        # Demonstrates threat intelligence even without an active internet or API key
        simulated_score = self._offline_threat_score(ip_address)
        self.db.cache_threat_info(
            ip_address=ip_address,
            threat_score=simulated_score["threat_score"],
            total_reports=simulated_score["total_reports"],
            country_code=simulated_score["country_code"],
            isp=simulated_score["isp"]
        )
        return simulated_score

    def _offline_threat_score(self, ip_address):
        """Simulates threat score for known malicious test ranges (e.g., botnets, scanners)."""
        octets = ip_address.split(".")
        if len(octets) == 4:
            # Deterministic hash for simulation so same IP gives consistent viva results
            val = (int(octets[0]) * 3 + int(octets[3]) * 7) % 100
            if val > 65:
                return {
                    "ip_address": ip_address,
                    "threat_score": val,
                    "total_reports": val // 4,
                    "is_whitelisted": 0,
                    "country_code": "RU" if val > 80 else "CN",
                    "isp": "Known Scanning Subnet (Simulated Feed)",
                    "cached": False
                }
        return {
            "ip_address": ip_address,
            "threat_score": 5,
            "total_reports": 0,
            "is_whitelisted": 0,
            "country_code": "US",
            "isp": "Public Cloud / Clean IP",
            "cached": False
        }

if __name__ == "__main__":
    ti = ThreatIntelligence()
    test_ip = "185.220.101.5"  # Well known Tor exit / scanner test IP
    res = ti.lookup_ip(test_ip)
    print(f"Threat Intel Result for {test_ip}: {json.dumps(res, indent=2)}")
