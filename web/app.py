import os
import sys
from pathlib import Path
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

import config
from database.db_manager import DatabaseManager
from core.threat_intel import ThreatIntelligence
from core.sniffer import get_sniffer

app = Flask(
    __name__,
    template_folder=str(ROOT_DIR / "web" / "templates"),
    static_folder=str(ROOT_DIR / "web" / "static")
)
app.secret_key = config.SECRET_KEY

# Upload folder for PCAP files
UPLOAD_FOLDER = ROOT_DIR / "data" / "sample_pcaps"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)

db = DatabaseManager()
threat_intel = ThreatIntelligence(db)
sniffer = get_sniffer()

# ----------------- Web UI Routes -----------------

@app.route("/")
def dashboard():
    """Main Cyber SOC Dashboard view."""
    stats = db.get_alert_statistics()
    recent_alerts = db.get_recent_alerts(limit=10)
    is_sniffing = sniffer.is_running
    return render_template(
        "dashboard.html",
        stats=stats,
        recent_alerts=recent_alerts,
        is_sniffing=is_sniffing
    )

@app.route("/alerts")
def alerts_page():
    """Detailed Security Alerts page."""
    alerts = db.get_recent_alerts(limit=100)
    return render_template("alerts.html", alerts=alerts)

@app.route("/pcap")
def pcap_page():
    """PCAP file upload & analysis tool."""
    return render_template("pcap_analysis.html")

@app.route("/threat-lookup")
def threat_lookup_page():
    """Manual IP Threat Intelligence checker."""
    return render_template("threat_lookup.html")

# ----------------- REST APIs for AJAX / Dashboard -----------------

@app.route("/api/stats")
def api_stats():
    """Returns real-time dashboard statistics and charts data."""
    stats = db.get_alert_statistics()
    stats["is_sniffing"] = sniffer.is_running
    stats["total_packets_sniffed"] = sniffer.packet_count
    return jsonify(stats)

@app.route("/api/recent-alerts")
def api_recent_alerts():
    """Returns top 15 recent alerts for live ticker/table."""
    alerts = db.get_recent_alerts(limit=15)
    return jsonify(alerts)

@app.route("/api/sniffer/toggle", methods=["POST"])
def api_sniffer_toggle():
    """Starts or stops the background Scapy packet sniffer."""
    action = request.json.get("action", "")
    if action == "start":
        sniffer.start_live_capture()
        return jsonify({"status": "started", "message": "Live packet capture started."})
    elif action == "stop":
        sniffer.stop_live_capture()
        return jsonify({"status": "stopped", "message": "Packet capture stopped."})
    return jsonify({"status": "error", "message": "Invalid action."}), 400

@app.route("/api/threat-check", methods=["POST"])
def api_threat_check():
    """Checks threat reputation for a given IP address."""
    data = request.json or {}
    ip = data.get("ip_address", "").strip()
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    result = threat_intel.lookup_ip(ip)
    return jsonify(result)

@app.route("/api/upload-pcap", methods=["POST"])
def api_upload_pcap():
    """Handles PCAP file upload and executes intrusion analysis."""
    if "pcap_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["pcap_file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng")):
        return jsonify({"error": "Only .pcap and .pcapng files are supported"}), 400

    filename = secure_filename(file.filename)
    filepath = Path(app.config["UPLOAD_FOLDER"]) / filename
    file.save(str(filepath))

    # Process PCAP via sniffer pipeline
    report = sniffer.process_pcap_file(filepath)
    return jsonify(report)

if __name__ == "__main__":
    print(f"[*] Starting AI-NIDS SOC Dashboard on http://{config.WEB_HOST}:{config.WEB_PORT}")
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, debug=config.DEBUG_MODE)
