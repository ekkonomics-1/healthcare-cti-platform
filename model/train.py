import pandas as pd
import numpy as np
import sqlite3
import pickle
import json
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from config.config import DATABASE_PATH, THREAT_LABELS

IOC_TYPE_MAP = {"ip": 0, "domain": 1, "url": 2, "hash": 3, "email": 4}

def load_training_data():
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("SELECT ioc, ioc_type, source, tags, confidence, is_healthcare, is_c2, first_seen FROM iocs")
    rows = c.fetchall()
    conn.close()
    
    if not rows:
        print("No data in database. Running collector first...")
        return None, None
    
    data = []
    for row in rows:
        ioc, ioc_type, source, tags_json, confidence, is_healthcare, is_c2, first_seen = row
        
        age_hours = 0
        if first_seen:
            try:
                first_dt = datetime.fromisoformat(first_seen)
                age_hours = (datetime.now() - first_dt).total_seconds() / 3600
            except:
                age_hours = 0
        
        try:
            tags = json.loads(tags_json) if tags_json else []
        except:
            tags = []
        
        label = assign_label(confidence, is_healthcare, is_c2, tags)
        
        data.append({
            "ioc_type": IOC_TYPE_MAP.get(ioc_type, 1),
            "confidence": confidence,
            "age_hours": min(age_hours, 168),
            "is_healthcare": is_healthcare,
            "is_c2": is_c2,
            "source_count": 1,
            "label": label
        })
    
    df = pd.DataFrame(data)
    return df

def assign_label(confidence, is_healthcare, is_c2, tags):
    score = confidence
    
    if is_c2:
        score += 30
    if is_healthcare:
        score += 25
    
    if "ransomware" in str(tags).lower():
        score += 20
    if "malware" in str(tags).lower():
        score += 15
    
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    else:
        return "Low"

def train_model():
    df = load_training_data()
    
    if df is None or len(df) < 10:
        print("Insufficient training data. Need at least 10 IOCs.")
        return None
    
    X = df[["ioc_type", "confidence", "age_hours", "is_healthcare", "is_c2", "source_count"]]
    y = df["label"]
    
    label_map = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    y_encoded = y.map(label_map)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    print("Model Training Results:")
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    print(classification_report(y_test, y_pred))
    
    with open("model/rf_model.pkl", "wb") as f:
        pickle.dump(model, f)
    
    print("Model saved to model/rf_model.pkl")
    return model

if __name__ == "__main__":
    train_model()