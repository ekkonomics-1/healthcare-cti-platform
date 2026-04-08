import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
import sqlite3
import json
import time
from datetime import datetime, timedelta
from config.config import OTX_API_KEY, FEODO_URL, URLHAUS_URL, DATABASE_PATH

def init_db():
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS iocs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ioc TEXT UNIQUE,
                  ioc_type TEXT,
                  source TEXT,
                  tags TEXT,
                  first_seen TEXT,
                  last_seen TEXT,
                  confidence INTEGER,
                  is_healthcare INTEGER DEFAULT 0,
                  is_c2 INTEGER DEFAULT 0,
                  vt_score INTEGER DEFAULT 0,
                  vt_malicious INTEGER DEFAULT 0,
                  vt_suspicious INTEGER DEFAULT 0,
                  malware_family TEXT,
                  is_medical_device INTEGER DEFAULT 0)''')
    
    try:
        c.execute("ALTER TABLE iocs ADD COLUMN vt_score INTEGER DEFAULT 0")
    except:
        pass
    try:
        c.execute("ALTER TABLE iocs ADD COLUMN vt_malicious INTEGER DEFAULT 0")
    except:
        pass
    try:
        c.execute("ALTER TABLE iocs ADD COLUMN vt_suspicious INTEGER DEFAULT 0")
    except:
        pass
    try:
        c.execute("ALTER TABLE iocs ADD COLUMN malware_family TEXT")
    except:
        pass
    try:
        c.execute("ALTER TABLE iocs ADD COLUMN is_medical_device INTEGER DEFAULT 0")
    except:
        pass
    
    conn.commit()
    return conn

def save_ioc(conn, ioc, ioc_type, source, tags=None, confidence=50):
    now = datetime.now().isoformat()
    tags_str = json.dumps(tags) if tags else "[]"
    
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO iocs 
                (ioc, ioc_type, source, tags, first_seen, last_seen, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
             (ioc, ioc_type, source, tags_str, now, now, confidence))
    conn.commit()

def fetch_otx_pulses():
    if not OTX_API_KEY:
        print("OTX_API_KEY not set")
        return []
    
    headers = {"X-OTX-API-KEY": OTX_API_KEY, "Content-Type": "application/json"}
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()
            pulses = []
            for pulse in data.get("results", [])[:50]:
                tags = pulse.get("tags", [])
                for ind in pulse.get("indicators", []):
                    ioc_data = {
                        "ioc": ind.get("indicator"),
                        "type": ind.get("type"),
                        "source": "OTX",
                        "tags": tags,
                        "confidence": ind.get("confidence", 50)
                    }
                    pulses.append(ioc_data)
            print(f"Fetched {len(pulses)} IOCs from OTX")
            return pulses
    except Exception as e:
        print(f"OTX fetch error: {e}")
    return []

def fetch_feodo():
    try:
        response = requests.get(FEODO_URL, timeout=30)
        if response.status_code == 200:
            data = response.json()
            iocs = []
            entries = data.get("feodo_ip_list", []) if isinstance(data, dict) else data
            for entry in entries:
                ip = entry.get("ip_address") if isinstance(entry, dict) else entry
                if ip:
                    iocs.append({
                        "ioc": ip,
                        "type": "ip",
                        "source": "Feodo",
                        "tags": ["c2", "botnet"],
                        "confidence": 90
                    })
            print(f"Fetched {len(iocs)} IOCs from Feodo")
            return iocs
    except Exception as e:
        print(f"Feodo fetch error: {e}")
    return []

def fetch_urlhaus():
    try:
        response = requests.get(URLHAUS_URL, timeout=60)
        if response.status_code == 200:
            data = response.json()
            iocs = []
            url_count = 0
            for entry in data.get("urls", [])[:500]:
                url = entry.get("url")
                if url:
                    threat = entry.get("threat", "malware_download")
                    confidence = 70 if threat == "malware_download" else 50
                    
                    iocs.append({
                        "ioc": url,
                        "type": "url",
                        "source": "URLhaus",
                        "tags": entry.get("tags", []),
                        "confidence": confidence
                    })
                    url_count += 1
            print(f"Fetched {len(iocs)} IOCs from URLhaus")
            return iocs
    except Exception as e:
        print(f"URLhaus fetch error: {e}")
    return []

def is_healthcare_related(tags, ioc_value=""):
    healthcare_keywords = ["healthcare", "medical", "hospital", "ransomware", "hl7", 
                        "dicom", "emr", "ehr", "pharma", "OpenEMR", "med", "fhir", 
                        "medical", "patient", "clinical"]
    
    medical_device_keywords = ["iot", "medical device", "diagnostic", "imaging", "scanner", "pacs", "ris"]
    
    if not tags:
        tags = []
    tags_lower = [str(t).lower() for t in tags]
    tag_text = " ".join(tags_lower)
    
    ioc_lower = str(ioc_value).lower()
    
    for kw in healthcare_keywords:
        if kw in tag_text or kw in ioc_lower:
            return True
    
    for kw in medical_device_keywords:
        if kw in ioc_lower:
            return True
    
    return False

def is_medical_device(ioc_value):
    device_patterns = ["pacs", "ris", "imaging", "scanner", "mri", "ct scan", "ultrasound",
                   "diagnostic", "monitore", "defibrill", "pacemaker", "insulin pump"]
    
    ioc_lower = str(ioc_value).lower()
    return any(p in ioc_lower for p in device_patterns)

def collect_all_iocs():
    conn = init_db()
    
    all_iocs = []
    all_iocs.extend(fetch_otx_pulses())
    time.sleep(2)
    all_iocs.extend(fetch_feodo())
    time.sleep(2)
    all_iocs.extend(fetch_urlhaus())
    
    for ioc_data in all_iocs:
        ioc_value = ioc_data.get("ioc", "")
        is_healthcare = 1 if is_healthcare_related(ioc_data.get("tags"), ioc_value) else 0
        is_c2 = 1 if "c2" in str(ioc_data.get("tags")).lower() else 0
        is_med_device = 1 if is_medical_device(ioc_value) else 0
        
        save_ioc(conn, ioc_data["ioc"], ioc_data["type"], ioc_data["source"],
               ioc_data.get("tags"), ioc_data.get("confidence", 50))
    
    conn.close()
    print(f"Total IOCs collected: {len(all_iocs)}")
    return all_iocs

if __name__ == "__main__":
    collect_all_iocs()