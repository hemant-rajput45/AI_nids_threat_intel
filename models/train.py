import os
import sys
import json
import urllib.request
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

import config

# Key features extracted from packets/flows for ML detection
FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "same_srv_rate",
    "diff_srv_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate"
]

def generate_synthetic_dataset(n_samples=5000):
    """Generates synthetic network flows simulating Normal, DoS, PortScan, and Probe traffic."""
    print("[*] Generating realistic benchmark network dataset...")
    np.random.seed(42)
    
    classes = ["Normal", "DoS", "PortScan", "Probe"]
    probs = [0.60, 0.20, 0.12, 0.08]
    labels = np.random.choice(classes, size=n_samples, p=probs)
    
    data = []
    for label in labels:
        if label == "Normal":
            row = {
                "duration": np.random.exponential(1.5),
                "protocol_type": np.random.choice(["tcp", "udp", "icmp"], p=[0.75, 0.20, 0.05]),
                "service": np.random.choice(["http", "https", "dns", "smtp", "ftp"]),
                "flag": "SF",
                "src_bytes": int(np.random.normal(500, 200)),
                "dst_bytes": int(np.random.normal(4000, 1500)),
                "count": int(np.random.randint(1, 15)),
                "srv_count": int(np.random.randint(1, 10)),
                "same_srv_rate": float(np.random.uniform(0.8, 1.0)),
                "diff_srv_rate": float(np.random.uniform(0.0, 0.1)),
                "dst_host_count": int(np.random.randint(5, 50)),
                "dst_host_srv_count": int(np.random.randint(5, 50)),
                "dst_host_same_srv_rate": float(np.random.uniform(0.8, 1.0)),
                "dst_host_diff_srv_rate": float(np.random.uniform(0.0, 0.1)),
                "dst_host_same_src_port_rate": float(np.random.uniform(0.0, 0.2)),
                "label": "Normal"
            }
        elif label == "DoS":  # High packet volume, tiny payload, SYN without ACK (e.g. S0 flag)
            row = {
                "duration": float(np.random.uniform(0.0, 0.2)),
                "protocol_type": "tcp",
                "service": np.random.choice(["http", "private", "other"]),
                "flag": np.random.choice(["S0", "REJ"]),
                "src_bytes": int(np.random.randint(0, 100)),
                "dst_bytes": 0,
                "count": int(np.random.randint(100, 500)),
                "srv_count": int(np.random.randint(100, 500)),
                "same_srv_rate": float(np.random.uniform(0.9, 1.0)),
                "diff_srv_rate": float(np.random.uniform(0.0, 0.05)),
                "dst_host_count": 255,
                "dst_host_srv_count": int(np.random.randint(10, 50)),
                "dst_host_same_srv_rate": float(np.random.uniform(0.1, 0.3)),
                "dst_host_diff_srv_rate": float(np.random.uniform(0.6, 0.9)),
                "dst_host_same_src_port_rate": float(np.random.uniform(0.8, 1.0)),
                "label": "DoS"
            }
        elif label == "PortScan":  # Scanning different ports on target host
            row = {
                "duration": float(np.random.uniform(0.0, 0.5)),
                "protocol_type": np.random.choice(["tcp", "udp"]),
                "service": np.random.choice(["private", "other", "echo"]),
                "flag": np.random.choice(["RSTR", "REJ", "S0"]),
                "src_bytes": int(np.random.randint(0, 40)),
                "dst_bytes": 0,
                "count": int(np.random.randint(30, 150)),
                "srv_count": int(np.random.randint(1, 5)),
                "same_srv_rate": float(np.random.uniform(0.0, 0.1)),
                "diff_srv_rate": float(np.random.uniform(0.7, 1.0)),
                "dst_host_count": 255,
                "dst_host_srv_count": int(np.random.randint(1, 10)),
                "dst_host_same_srv_rate": float(np.random.uniform(0.0, 0.05)),
                "dst_host_diff_srv_rate": float(np.random.uniform(0.8, 1.0)),
                "dst_host_same_src_port_rate": float(np.random.uniform(0.0, 0.1)),
                "label": "PortScan"
            }
        else:  # Probe / Vulnerability scanning
            row = {
                "duration": float(np.random.uniform(0.5, 5.0)),
                "protocol_type": np.random.choice(["tcp", "icmp"]),
                "service": np.random.choice(["finger", "ftp", "telnet", "smtp"]),
                "flag": np.random.choice(["RSTO", "SF", "SH"]),
                "src_bytes": int(np.random.randint(10, 300)),
                "dst_bytes": int(np.random.randint(0, 150)),
                "count": int(np.random.randint(5, 40)),
                "srv_count": int(np.random.randint(1, 15)),
                "same_srv_rate": float(np.random.uniform(0.2, 0.6)),
                "diff_srv_rate": float(np.random.uniform(0.3, 0.7)),
                "dst_host_count": int(np.random.randint(50, 200)),
                "dst_host_srv_count": int(np.random.randint(2, 30)),
                "dst_host_same_srv_rate": float(np.random.uniform(0.1, 0.4)),
                "dst_host_diff_srv_rate": float(np.random.uniform(0.4, 0.8)),
                "dst_host_same_src_port_rate": float(np.random.uniform(0.2, 0.5)),
                "label": "Probe"
            }
        data.append(row)

    df = pd.DataFrame(data)
    # Ensure no negative numericals
    df["src_bytes"] = df["src_bytes"].clip(lower=0)
    df["dst_bytes"] = df["dst_bytes"].clip(lower=0)
    return df

def train_and_save_model():
    """Trains Random Forest model, evaluates performance, and serializes model artifacts."""
    df = generate_synthetic_dataset(n_samples=8000)
    
    # Save processed CSV for reference
    processed_path = config.DATA_DIR / "processed" / "nids_dataset.csv"
    df.to_csv(processed_path, index=False)
    print(f"[+] Dataset saved to {processed_path}")

    X = df[FEATURE_COLUMNS].copy()
    y = df["label"].copy()

    # Categorical Encoders for protocol, service, and flags
    cat_columns = ["protocol_type", "service", "flag"]
    encoders = {}
    for col in cat_columns:
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col].astype(str))
        encoders[col] = {val: int(idx) for idx, val in enumerate(le.classes_)}

    # Target Label Encoder
    target_le = LabelEncoder()
    y_encoded = target_le.fit_transform(y)
    
    # Train-Test Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    # Standard Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Random Forest Model
    print("[*] Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=100, 
        max_depth=16, 
        random_state=42, 
        n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)

    # Evaluation
    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    print(f"\n================ Model Evaluation ================")
    print(f"Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=target_le.classes_))
    print("==================================================\n")

    # Serialize artifacts
    joblib.dump(model, config.MODEL_FILE)
    joblib.dump(scaler, config.SCALER_FILE)
    joblib.dump(target_le, config.LABEL_ENCODER_FILE)

    # Save feature metadata & categorical map
    metadata = {
        "features": FEATURE_COLUMNS,
        "categorical_encoders": encoders,
        "classes": list(target_le.classes_),
        "accuracy": round(float(acc), 4)
    }
    with open(config.MODELS_DIR / "model_metadata.json", "w") as f:
        json.dump(metadata, f, indent=4)

    print(f"[+] Successfully saved model to {config.MODEL_FILE}")
    print(f"[+] Successfully saved scaler to {config.SCALER_FILE}")
    print(f"[+] Successfully saved label encoder to {config.LABEL_ENCODER_FILE}")

if __name__ == "__main__":
    train_and_save_model()
