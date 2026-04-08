import requests
import time
import sqlite3
import json
from config.config import VT_API_KEY, DATABASE_PATH

VT_BASE_URL = "https://www.virustotal.com/api/v3"

def get_vt_reputation(ioc_type, ioc_value):
    if not VT_API_KEY:
        return None
    
    endpoints = {
        "ip": f"ip_addresses/{ioc_value}",
        "domain": f"domains/{ioc_value}",
        "url": f"urls/{ioc_value}",
        "file": f"files/{ioc_value}"
    }
    
    endpoint = endpoints.get(ioc_type.lower())
    if not endpoint:
        return None
    
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(f"{VT_BASE_URL}/{endpoint}", headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return parse_vt_response(ioc_type, data)
        elif response.status_code == 404:
            return {"found": False, "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
    except Exception as e:
        print(f"VT API error for {ioc_value}: {e}")
    
    return None

def parse_vt_response(ioc_type, data):
    if ioc_type in ["ip", "domain"]:
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_results", {})
        
        malicious = sum(1 for r in last_analysis.values() if r.get("category") == "malicious")
        suspicious = sum(1 for r in last_analysis.values() if r.get("category") == "suspicious")
        harmless = sum(1 for r in last_analysis.values() if r.get("category") == "harmless")
        undetected = sum(1 for r in last_analysis.values() if r.get("category") == "undetected")
        
        return {
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": malicious + suspicious + harmless + undetected
        }
    elif ioc_type == "url":
        attributes = data.get("data", {}).get("attributes", {})
        last_analysis = attributes.get("last_analysis_results", {})
        
        malicious = sum(1 for r in last_analysis.values() if r.get("category") == "malicious")
        suspicious = sum(1 for r in last_analysis.values() if r.get("category") == "suspicious")
        
        return {
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": malicious + suspicious
        }
    
    return {"found": False}

def enrich_ioc_with_vt(ioc_id, ioc_type, ioc_value):
    result = get_vt_reputation(ioc_type, ioc_value)
    
    if result and result.get("found"):
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        
        malicious = result.get("malicious", 0)
        suspicious = result.get("suspicious", 0)
        total = result.get("total_engines", 0)
        
        vt_score = 0
        if total > 0:
            vt_score = int(((malicious + suspicious) / total) * 100)
        
        c.execute("""UPDATE iocs 
                    SET vt_malicious = ?, vt_suspicious = ?, vt_score = ?, last_seen = datetime('now')
                    WHERE id = ?""",
                 (malicious, suspicious, vt_score, ioc_id))
        
        conn.commit()
        conn.close()
        
        return {"ioc": ioc_value, "vt_score": vt_score, "malicious": malicious}
    
    return None

def enrich_all_iocs(limit_per_minute=4):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    c.execute("""SELECT id, ioc, ioc_type FROM iocs 
                WHERE vt_score IS NULL OR vt_score = 0
                ORDER BY confidence DESC
                LIMIT 500""")
    
    iocs = c.fetchall()
    conn.close()
    
    if not iocs:
        print("No IOCs to enrich")
        return 0
    
    enriched = 0
    rate_limit_counter = 0
    
    print(f"Enriching {len(iocs)} IOCs with VirusTotal...")
    
    for ioc_id, ioc_value, ioc_type in iocs:
        result = enrich_ioc_with_vt(ioc_id, ioc_type, ioc_value)
        
        if result:
            enriched += 1
            print(f"Enriched {ioc_value}: {result.get('malicious', 0)} malicious, VT score: {result.get('vt_score', 0)}")
        
        rate_limit_counter += 1
        
        if rate_limit_counter >= limit_per_minute:
            print("Rate limit reached, waiting 60 seconds...")
            time.sleep(60)
            rate_limit_counter = 0
        
        time.sleep(15)
    
    print(f"VT Enrichment complete: {enriched} IOCs enriched")
    return enriched

def check_vt_reputation(ioc_type, ioc_value):
    return get_vt_reputation(ioc_type, ioc_value)

if __name__ == "__main__":
    enrich_all_iocs()