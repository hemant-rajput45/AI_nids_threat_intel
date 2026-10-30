-- SQLite Schema for AI-Powered NIDS & Threat Intelligence System

-- 1. Security Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    source_port INTEGER,
    dest_port INTEGER,
    protocol TEXT DEFAULT 'TCP',
    attack_type TEXT NOT NULL,       -- DoS, PortScan, Probe, Malicious, etc.
    confidence REAL DEFAULT 0.0,     -- ML Confidence (0.0 to 1.0)
    threat_score INTEGER DEFAULT 0,  -- Threat Intel Reputation (0 to 100)
    severity TEXT DEFAULT 'Low',     -- Low, Medium, High, Critical
    status TEXT DEFAULT 'New',       -- New, Investigated, Blocked
    details TEXT
);

-- 2. Raw Network Logs Table
CREATE TABLE IF NOT EXISTS network_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip TEXT NOT NULL,
    dest_ip TEXT NOT NULL,
    source_port INTEGER,
    dest_port INTEGER,
    protocol TEXT DEFAULT 'TCP',
    packet_length INTEGER DEFAULT 0,
    tcp_flags TEXT DEFAULT '',
    is_anomaly INTEGER DEFAULT 0     -- 0 = Normal, 1 = Suspicious/Anomaly
);

-- 3. Threat Intelligence Cache Table (To prevent rate-limiting)
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ip_address TEXT PRIMARY KEY,
    threat_score INTEGER DEFAULT 0,
    total_reports INTEGER DEFAULT 0,
    is_whitelisted INTEGER DEFAULT 0,
    country_code TEXT DEFAULT 'Unknown',
    isp TEXT DEFAULT 'Unknown',
    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for fast querying
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON network_logs (timestamp DESC);
