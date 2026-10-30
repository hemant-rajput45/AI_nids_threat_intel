import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
DATABASE_PATH = BASE_DIR / "database" / "nids.db"
SAMPLE_PCAPS_DIR = DATA_DIR / "sample_pcaps"

# Create directories if they do not exist
for directory in [DATA_DIR, DATA_DIR / "raw", DATA_DIR / "processed", SAMPLE_PCAPS_DIR, MODELS_DIR, BASE_DIR / "database"]:
    directory.mkdir(parents=True, exist_ok=True)

# Machine Learning Artifacts
MODEL_FILE = MODELS_DIR / "nids_classifier.pkl"
SCALER_FILE = MODELS_DIR / "scaler.pkl"
LABEL_ENCODER_FILE = MODELS_DIR / "label_encoder.pkl"

# Threat Intelligence Configuration
# You can replace this with your free AbuseIPDB API key from https://www.abuseipdb.com/
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
THREAT_CACHE_TTL_HOURS = 24

# Network Sniffer Configuration
DEFAULT_INTERFACE = None  # None selects default gateway interface in Scapy
SNIFFER_PACKET_COUNT = 0  # 0 for infinite continuous sniffing
BATCH_PROCESSING_INTERVAL = 3  # Process flows every N seconds

# Web Server Configuration
WEB_HOST = "127.0.0.1"
WEB_PORT = 5000
DEBUG_MODE = True
SECRET_KEY = os.getenv("SECRET_KEY", "super-secret-nids-key-2026")
