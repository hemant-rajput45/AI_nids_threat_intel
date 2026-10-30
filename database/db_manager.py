import sqlite3
import os
import sys
from pathlib import Path
from datetime import datetime

# Add root directory to sys.path to easily import config
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

import config

class DatabaseManager:
    def __init__(self, db_path=None):
        self.db_path = str(db_path or config.DATABASE_PATH)
        self.init_db()

    def get_connection(self):
        """Creates and returns a connection to the SQLite database with dictionary rows."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        """Applies the SQL schema to initialize tables."""
        schema_path = Path(__file__).parent / "schema.sql"
        if not schema_path.exists():
            return

        with open(schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        with self.get_connection() as conn:
            conn.executescript(schema_sql)
            conn.commit()

    # ---------------- Alerts Operations ----------------
    def insert_alert(self, source_ip, dest_ip, source_port, dest_port, protocol, 
                     attack_type, confidence, threat_score, severity, details=""):
        """Inserts a new security intrusion alert."""
        query = """
            INSERT INTO alerts 
            (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, attack_type, confidence, threat_score, severity, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (
                now, source_ip, dest_ip, source_port, dest_port, protocol,
                attack_type, round(confidence, 3), threat_score, severity, details
            ))
            conn.commit()
            return cursor.lastrowid

    def get_recent_alerts(self, limit=50):
        """Fetches the most recent alerts."""
        query = "SELECT * FROM alerts ORDER BY id DESC LIMIT ?"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_alert_statistics(self):
        """Aggregates alert counts by severity and attack type for dashboard charts."""
        stats = {
            "total_alerts": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "by_attack_type": {},
            "top_attackers": []
        }
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Severity counts
            cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
            for row in cursor.fetchall():
                sev = str(row["severity"]).lower()
                if sev in stats:
                    stats[sev] = row["count"]
                stats["total_alerts"] += row["count"]

            # Attack type distribution
            cursor.execute("SELECT attack_type, COUNT(*) as count FROM alerts GROUP BY attack_type ORDER BY count DESC LIMIT 6")
            for row in cursor.fetchall():
                stats["by_attack_type"][row["attack_type"]] = row["count"]

            # Top 5 attacker IPs
            cursor.execute("""
                SELECT source_ip, COUNT(*) as attack_count, MAX(threat_score) as max_score 
                FROM alerts GROUP BY source_ip ORDER BY attack_count DESC LIMIT 5
            """)
            stats["top_attackers"] = [dict(row) for row in cursor.fetchall()]

        return stats

    # ---------------- Network Logs Operations ----------------
    def insert_log(self, source_ip, dest_ip, source_port, dest_port, protocol, packet_length, tcp_flags, is_anomaly=0):
        """Records a parsed network packet/flow log."""
        query = """
            INSERT INTO network_logs
            (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, packet_length, tcp_flags, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (
                now, source_ip, dest_ip, source_port, dest_port, protocol,
                packet_length, tcp_flags, is_anomaly
            ))
            conn.commit()

    def get_recent_logs(self, limit=30):
        """Retrieves latest network traffic logs."""
        query = "SELECT * FROM network_logs ORDER BY id DESC LIMIT ?"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    # ---------------- Threat Intel Cache Operations ----------------
    def get_cached_threat(self, ip_address):
        """Checks if threat intelligence score is already cached."""
        query = "SELECT * FROM threat_intel_cache WHERE ip_address = ?"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (ip_address,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def cache_threat_info(self, ip_address, threat_score, total_reports=0, is_whitelisted=0, country_code="Unknown", isp="Unknown"):
        """Saves or updates cached threat score."""
        query = """
            INSERT INTO threat_intel_cache 
            (ip_address, threat_score, total_reports, is_whitelisted, country_code, isp, last_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                threat_score=excluded.threat_score,
                total_reports=excluded.total_reports,
                is_whitelisted=excluded.is_whitelisted,
                country_code=excluded.country_code,
                isp=excluded.isp,
                last_checked=excluded.last_checked
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, (ip_address, threat_score, total_reports, is_whitelisted, country_code, isp, now))
            conn.commit()

if __name__ == "__main__":
    db = DatabaseManager()
    print(f"Database successfully initialized at: {db.db_path}")
