import pickle
import json
import numpy as np
import sqlite3
from datetime import datetime
from config.config import DATABASE_PATH, THREAT_LABELS

IOC_TYPE_MAP = {"ip": 0, "domain": 1, "url": 2, "hash": 3, "email": 4}

model = None

def load_model():
    global model
    try:
        with open("model/rf_model.pkl", "rb") as f:
            model = pickle.load(f)
        print("Model loaded successfully")
        return model
    except FileNotFoundError:
        print("Model not found. Run train.py first.")
        return None

def get_ioc_features(ioc_type, confidence, age_hours, is_healthcare, is_c2, source_count):
    return np.array([[
        IOC_TYPE_MAP.get(ioc_type, 1),
        confidence,
        min(age_hours, 168),
        is_healthcare,
        is_c2,
        source_count
    ]])

def predict(ioc, ioc_type="ip", confidence=50, age_hours=0, is_healthcare=0, is_c2=0, source_count=1):
    global model
    
    if model is None:
        load_model()
    
    if model is None:
        return {"label": "Medium", "confidence": 0.5, "explanation": "Model not available"}
    
    features = get_ioc_features(ioc_type, confidence, age_hours, is_healthcare, is_c2, source_count)
    
    proba = model.predict_proba(features)[0]
    prediction = model.predict(features)[0]
    
    label_map = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}
    label = label_map.get(prediction, "Medium")
    max_confidence = max(proba)
    
    explanation = build_explanation(ioc, ioc_type, confidence, is_healthcare, is_c2, label)
    
    return {
        "ioc": ioc,
        "label": label,
        "confidence": round(max_confidence, 2),
        "features": {
            "ioc_type": ioc_type,
            "confidence": confidence,
            "age_hours": age_hours,
            "is_healthcare": is_healthcare,
            "is_c2": is_c2,
            "source_count": source_count
        },
        "explanation": explanation
    }

def build_explanation(ioc, ioc_type, confidence, is_healthcare, is_c2, label):
    reasons = []
    
    if is_c2:
        reasons.append("Tagged as C2/botnet")
    if is_healthcare:
        reasons.append("Healthcare-related indicator")
    if confidence >= 70:
        reasons.append(f"High source confidence ({confidence}%)")
    if confidence >= 90:
        reasons.append("Confirmed malicious by multiple sources")
    
    if not reasons:
        reasons.append("Standard threat indicator")
    
    return f"{label} priority: {', '.join(reasons)}"

def score_ioc_from_db(ioc_id):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("SELECT ioc, ioc_type, source, tags, confidence, is_healthcare, is_c2, first_seen FROM iocs WHERE id=?", (ioc_id,))
    row = c.fetchone()
    conn.close()
    
    if not row:
        return None
    
    ioc, ioc_type, source, tags_json, confidence, is_healthcare, is_c2, first_seen = row
    
    age_hours = 0
    if first_seen:
        try:
            first_dt = datetime.fromisoformat(first_seen)
            age_hours = (datetime.now() - first_dt).total_seconds() / 3600
        except:
            age_hours = 0
    
    return predict(ioc, ioc_type, confidence, age_hours, is_healthcare, is_c2, 1)

if __name__ == "__main__":
    load_model()
    if model:
        result = predict("185.220.101.45", "ip", confidence=85, is_c2=1)
        print(result)