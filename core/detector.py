import json
from pathlib import Path
import sys
import numpy as np
import pandas as pd
import joblib

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.append(str(ROOT_DIR))

import config

class IntrusionDetector:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.metadata = {}
        self.load_artifacts()

    def load_artifacts(self):
        """Loads trained ML model, scaler, and metadata."""
        if config.MODEL_FILE.exists() and config.SCALER_FILE.exists() and config.LABEL_ENCODER_FILE.exists():
            self.model = joblib.load(config.MODEL_FILE)
            self.scaler = joblib.load(config.SCALER_FILE)
            self.label_encoder = joblib.load(config.LABEL_ENCODER_FILE)
            
            meta_path = config.MODELS_DIR / "model_metadata.json"
            if meta_path.exists():
                with open(meta_path, "r") as f:
                    self.metadata = json.load(f)
            print("[+] IntrusionDetector: ML model and preprocessing artifacts loaded.")
        else:
            raise FileNotFoundError("Model artifacts not found! Run 'python models/train.py' first.")

    def calculate_severity(self, attack_type, confidence, threat_score=0):
        """
        Combines ML Confidence and Threat Intelligence score to compute severity.
        Returns: 'Low', 'Medium', 'High', or 'Critical'
        """
        if attack_type == "Normal":
            return "Low"

        # Base composite score: (ML Confidence * 50) + (Threat Intel Score * 0.5)
        composite = (confidence * 50.0) + (threat_score * 0.5)

        if attack_type == "DoS":
            composite += 15
        elif attack_type == "Probe":
            composite += 5

        if composite >= 75:
            return "Critical"
        elif composite >= 50:
            return "High"
        elif composite >= 30:
            return "Medium"
        else:
            return "Low"

    def predict(self, feature_dict, threat_score=0):
        """
        Takes a dictionary of network flow features and outputs prediction.
        """
        features_list = self.metadata.get("features", [])
        encoders = self.metadata.get("categorical_encoders", {})

        # Prepare a clean row
        row = {}
        for feat in features_list:
            val = feature_dict.get(feat, 0)
            # Encode categoricals if required
            if feat in encoders:
                val_str = str(val).lower()
                mapping = encoders[feat]
                # Default to index 0 if unknown category encountered
                val = mapping.get(val_str, 0)
            row[feat] = float(val)

        df_single = pd.DataFrame([row])[features_list]
        scaled = self.scaler.transform(df_single)

        # Prediction and probabilities
        pred_idx = self.model.predict(scaled)[0]
        probs = self.model.predict_proba(scaled)[0]
        confidence = float(np.max(probs))
        predicted_class = self.label_encoder.inverse_transform([pred_idx])[0]

        is_attack = (predicted_class != "Normal")
        severity = self.calculate_severity(predicted_class, confidence, threat_score)

        return {
            "attack_type": predicted_class,
            "confidence": round(confidence, 4),
            "is_attack": bool(is_attack),
            "severity": severity,
            "threat_score": threat_score
        }

if __name__ == "__main__":
    detector = IntrusionDetector()
    # Test sample simulating SYN flood DoS
    sample_dos = {
        "duration": 0.05,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "S0",
        "src_bytes": 40,
        "dst_bytes": 0,
        "count": 350,
        "srv_count": 350,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 30,
        "dst_host_same_srv_rate": 0.2,
        "dst_host_diff_srv_rate": 0.8,
        "dst_host_same_src_port_rate": 0.95
    }
    result = detector.predict(sample_dos, threat_score=85)
    print("Inference Test Result:", json.dumps(result, indent=2))
