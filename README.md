# AI-Powered Network Intrusion Detection & Threat Intelligence System

An intelligent, real-time Cyber Security Operations Center (SOC) system combining **Machine Learning flow-based detection**, **Scapy packet inspection**, **Threat Intelligence IP reputation scoring**, and a **Flask-powered web monitoring dashboard**.

---

## 🌟 Key Features

1. **AI / Machine Learning Detection Engine**
   - **Multi-Class Classifier:** Random Forest trained to distinguish between **Normal**, **DoS (Denial of Service)**, **PortScan**, and **Probe/Vulnerability Scanning** attacks.
   - Flow feature extraction using statistical sliding window (duration, protocol, flag analysis, packet frequencies).

2. **Real-Time Packet Sniffing & PCAP Forensics (Scapy)**
   - **Live Sniffing Mode:** Inspects live incoming network traffic across network interfaces in real time.
   - **PCAP Forensics Mode:** Allows uploading `.pcap` or `.pcapng` capture files to perform offline security audits (crucial for viva presentations where firing live attacks is forbidden).

3. **Threat Intelligence Integration**
   - **AbuseIPDB Integration:** Queries suspicious external IPs against global threat databases.
   - **Local Cache:** SQLite caching layer prevents rate-limiting and speeds up lookups.
   - **Multi-Factor Risk Scoring:** Composite severity formula combining ML prediction confidence with IP reputation score:
     $$\text{Composite Risk} = (\text{ML Confidence} \times 50) + (\text{Threat Intel Score} \times 0.5)$$

4. **Security Operations Center (SOC) Web Dashboard (Flask)**
   - Dark-mode responsive cyber security UI.
   - Real-time stats and auto-refreshing charts (Chart.js) for attack types and severity distribution.
   - Filterable security incidents log with IP inspection links.
   - On-demand IP reputation audit tool.

---

## 📁 Project Directory Structure

```text
ai_nids_threat_intel/
│
├── data/
│   ├── raw/                      # Raw datasets
│   ├── processed/                # Preprocessed dataset CSVs
│   └── sample_pcaps/             # Pre-generated PCAPs for testing & demo
│
├── models/
│   ├── train.py                  # ML model training and evaluation script
│   ├── nids_classifier.pkl       # Serialized Random Forest model
│   ├── scaler.pkl                # StandardScaler object
│   ├── label_encoder.pkl         # Target label encoder
│   └── model_metadata.json       # Feature mappings & accuracy statistics
│
├── core/
│   ├── __init__.py
│   ├── sniffer.py                # Scapy packet capture & PCAP parsing engine
│   ├── feature_extractor.py      # Statistical flow feature extractor
│   ├── detector.py               # Real-time ML inference & severity calculator
│   └── threat_intel.py           # AbuseIPDB API client & offline feed emulator
│
├── database/
│   ├── schema.sql                # SQLite database schema
│   ├── db_manager.py             # Database CRUD helper
│   └── nids.db                   # SQLite database file
│
├── web/
│   ├── app.py                    # Flask application & REST endpoints
│   ├── static/
│   │   ├── css/style.css         # SOC dark cyber theme stylesheet
│   │   └── js/dashboard.js       # Real-time polling & Chart.js scripts
│   └── templates/
│       ├── base.html             # Base layout with sidebar
│       ├── dashboard.html        # Main SOC operations overview
│       ├── alerts.html           # Searchable alert history table
│       ├── pcap_analysis.html    # Drag-and-drop PCAP forensic tool
│       └── threat_lookup.html    # Manual IP reputation checker
│
├── scripts/
│   ├── seed_db.py                # Populates realistic demo records
│   └── simulate_attacks.py       # Generates sample DoS, PortScan, and Normal PCAPs
│
├── config.py                     # Central configuration settings
├── requirements.txt              # Project dependencies
└── README.md                     # Documentation & Viva guide
```

---

## 🚀 How to Run the Project

### Step 1: Install Dependencies
Open PowerShell or Terminal and run:
```bash
pip install -r requirements.txt
```

### Step 2: (Optional) Retrain the AI Model
The model is already pre-trained and saved in `models/`. If you want to train it again:
```bash
python models/train.py
```

### Step 3: (Optional) Seed Sample Data & Generate Test PCAPs
```bash
python scripts/seed_db.py
python scripts/simulate_attacks.py
```

### Step 4: Start the Web Dashboard
```bash
python web/app.py
```
Then open your browser and navigate to:
👉 **`http://127.0.0.1:5000`**

---

## 🎯 How to Demonstrate in College Viva

1. **Overview & Dashboard:**
   - Open `http://127.0.0.1:5000` and show the metrics cards, attack distribution doughnut chart, and live security incident alerts.
2. **PCAP Forensic Analysis (Best for Viva):**
   - Click **PCAP Forensics** in the sidebar.
   - Upload `data/sample_pcaps/sample_syn_flood_dos.pcap` or `sample_portscan.pcap`.
   - Click **Run AI Security Audit** and show how the system detects the intrusions.
3. **Threat Intelligence Check:**
   - Go to **Threat Intelligence** in the sidebar.
   - Click one of the test buttons (e.g., `185.220.101.5` Tor exit node) to demonstrate live IP reputation lookup, abuse report counts, and geographic origin.
4. **Live Network Sniffing:**
   - Click the **Start Sniffer** button in the top navbar.
   - The sniffer starts capturing packets in a background thread, updating the packet counter in real time.

---

## ❓ Frequently Asked Viva Questions & Answers

**Q1: Why did you choose Random Forest instead of a simple threshold-based rule engine?**
> *Answer:* Traditional firewalls use fixed signatures (like blocking port 80 if traffic exceeds X packets). Attackers bypass this with distributed scans or stealthy packet rates. Random Forest analyzes non-linear multi-variate flow statistics (flags, payload ratios, same-host rates) to detect zero-day and stealth attacks with high accuracy.

**Q2: What is the purpose of Threat Intelligence integration?**
> *Answer:* An ML model can predict that an incoming packet looks suspicious, but Threat Intelligence validates whether the source IP has a historical reputation for launching attacks, hosting botnets, or brute-forcing servers. Combining both minimizes false positives.

**Q3: How does the system handle high-volume network traffic?**
> *Answer:* We use a sliding time-window feature extractor that aggregates packets into bidirectional connection flows, normal traffic is sampled, and IP lookups are cached in SQLite to prevent network bottlenecks.
