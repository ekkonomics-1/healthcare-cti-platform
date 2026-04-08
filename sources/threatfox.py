import requests
import sqlite3
import json
import time
from config.config import THREATFOX_URL, DATABASE_PATH

def fetch_threatfox(malware_category=None, limit=100):
    payload = {
        "query": "get_malware",
        "limit": limit
    }
    
    if malware_category:
        payload["malware_name"] = malware_category
    
    try:
        response = requests.post(THREATFOX_URL, json=payload, timeout=30)
        if response.status_code == 200:
            data = response.json()
            return parse_threatfox_response(data)
    except Exception as e:
        print(f"ThreatFox API error: {e}")
    
    return []

def parse_threatfox_response(data):
    iocs = []
    
    if data.get("query_status") == "ok":
        for entry in data.get("data", []):
            ioc_data = entry.get("ioc", {})
            
            ioc_value = ioc_data.get("ioc_value")
            ioc_type = ioc_data.get("ioc_type", "url")
            malware = entry.get("malware_alias", [])
            malware_family = entry.get("malware_name", "Unknown")
            first_seen = ioc_data.get("first_seen")
            tags = ioc_data.get("tags", [])
            
            if ioc_value:
                iocs.append({
                    "ioc": ioc_value,
                    "ioc_type": ioc_type,
                    "source": "ThreatFox",
                    "malware_family": malware_family[0] if malware else "Unknown",
                    "tags": tags,
                    "confidence": 85,
                    "first_seen": first_seen
                })
    
    return iocs

def collect_threatfox_iocs():
    malware_families = [
        "Emotet",
        "TrickBot", 
        "QakBot",
        "IcedID",
        "AsyncRAT",
        "FormBook",
        "RedLineStealer",
        "RaccoonStealer",
        "RecordBreaker",
        "CobaltStrike"
    ]
    
    all_iocs = []
    
    for family in malware_families:
        print(f"Fetching {family} IOCs from ThreatFox...")
        iocs = fetch_threatfox(family, limit=50)
        all_iocs.extend(iocs)
        print(f"  Found {len(iocs)} IOCs for {family}")
        time.sleep(2)
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    stored = 0
    for ioc_data in all_iocs:
        try:
            tags_json = json.dumps(ioc_data.get("tags", []))
            c.execute("""INSERT OR IGNORE INTO iocs 
                        (ioc, ioc_type, source, tags, first_seen, last_seen, confidence, malware_family)
                        VALUES (?, ?, ?, ?, ?, datetime('now'), ?, ?)""",
                     (ioc_data["ioc"], ioc_data["ioc_type"], ioc_data["source"],
                      tags_json, ioc_data.get("first_seen"),
                      ioc_data["confidence"], ioc_data.get("malware_family", "Unknown")))
            stored += 1
        except Exception as e:
            pass
    
    conn.commit()
    conn.close()
    
    print(f"ThreatFox collection complete: {stored} new IOCs stored")
    return stored

if __name__ == "__main__":
    collect_threatfox_iocs()