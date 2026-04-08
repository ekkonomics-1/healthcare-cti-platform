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
                  is_c2 INTEGER DEFAULT 0)''')
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
            for entry in data.get("feodo_ip_list", []):
                iocs.append({
                    "ioc": entry.get("ip_address"),
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
        response = requests.get(URLHAUS_URL, timeout=30)
        if response.status_code == 200:
            data = response.json()
            iocs = []
            for entry in data.get("urls", [])[:100]:
                url = entry.get("url")
                if url:
                    iocs.append({
                        "ioc": url,
                        "type": "url",
                        "source": "URLhaus",
                        "tags": entry.get("tags", []),
                        "confidence": entry.get("threat", 50)
                    })
            print(f"Fetched {len(iocs)} IOCs from URLhaus")
            return iocs
    except Exception as e:
        print(f"URLhaus fetch error: {e}")
    return []

def is_healthcare_related(tags):
    healthcare_keywords = ["healthcare", "medical", "hospital", "ransomware", "hl7", 
                        "dicom", "emr", "ehr", "pharma", "OpenEMR", "med"]
    if not tags:
        return False
    tags_lower = [str(t).lower() for t in tags]
    return any(kw in " ".join(tags_lower) for kw in healthcare_keywords)

def collect_all_iocs():
    conn = init_db()
    
    all_iocs = []
    all_iocs.extend(fetch_otx_pulses())
    time.sleep(2)
    all_iocs.extend(fetch_feodo())
    time.sleep(2)
    all_iocs.extend(fetch_urlhaus())
    
    for ioc_data in all_iocs:
        is_healthcare = 1 if is_healthcare_related(ioc_data.get("tags")) else 0
        is_c2 = 1 if "c2" in str(ioc_data.get("tags")).lower() else 0
        
        ioc_entry = ioc_data.copy()
        ioc_entry["is_healthcare"] = is_healthcare
        ioc_entry["is_c2"] = is_c2
        
        save_ioc(conn, ioc_data["ioc"], ioc_data["type"], ioc_data["source"],
               ioc_data.get("tags"), ioc_data.get("confidence", 50))
    
    conn.close()
    print(f"Total IOCs collected: {len(all_iocs)}")
    return all_iocs

if __name__ == "__main__":
    collect_all_iocs()