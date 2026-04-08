import requests
import sqlite3
import json
import time
from datetime import datetime
from config.config import NVD_API_URL, DATABASE_PATH

OPENEMR_KEYWORDS = ["openemr", "open-emr", "openemr electronic medical record"]

def fetch_openemr_cves(keyword="openemr", limit=50):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit
    }
    
    try:
        response = requests.get(NVD_API_URL, params=params, timeout=30)
        if response.status_code == 200:
            data = response.json()
            return parse_nvd_response(data, keyword)
    except Exception as e:
        print(f"NVD API error: {e}")
    
    return []

def parse_nvd_response(data, keyword):
    cves = []
    
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        
        cve_id = cve.get("id")
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        metrics = cve.get("metrics", {})
        cvss = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        
        base_score = cvss.get("baseScore", 0)
        severity = cvss.get("baseSeverity", "UNKNOWN")
        
        references = cve.get("references", [])
        ref_urls = [r.get("url") for r in references[:3]]
        
        published = cve.get("published")
        
        cves.append({
            "cve_id": cve_id,
            "description": description[:500],
            "base_score": base_score,
            "severity": severity,
            "reference_urls": ref_urls,
            "published": published,
            "keyword": keyword
        })
    
    return cves

def save_openemr_cves():
    all_cves = []
    
    for keyword in OPENEMR_KEYWORDS:
        print(f"Fetching CVEs for {keyword}...")
        cves = fetch_openemr_cves(keyword, limit=30)
        all_cves.extend(cves)
        print(f"  Found {len(cves)} CVEs for {keyword}")
        time.sleep(6)
    
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    c.execute("""CREATE TABLE IF NOT EXISTS cves
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 cve_id TEXT UNIQUE,
                 description TEXT,
                 base_score REAL,
                 severity TEXT,
                 reference_urls TEXT,
                 published TEXT,
                 keyword TEXT,
                 last_updated TEXT)""")
    
    stored = 0
    seen_cves = set()
    
    for cve_data in all_cves:
        if cve_data["cve_id"] in seen_cves:
            continue
        seen_cves.add(cve_data["cve_id"])
        
        try:
            c.execute("""INSERT OR REPLACE INTO cves 
                        (cve_id, description, base_score, severity, reference_urls, published, keyword, last_updated)
                        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))""",
                     (cve_data["cve_id"], cve_data["description"], cve_data["base_score"],
                      cve_data["severity"], json.dumps(cve_data["reference_urls"]),
                      cve_data["published"], cve_data["keyword"]))
            stored += 1
        except Exception as e:
            pass
    
    conn.commit()
    conn.close()
    
    print(f"OpenEMR CVE collection complete: {stored} CVEs stored")
    return stored

def get_recent_cves(limit=10):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    c.execute("""SELECT cve_id, base_score, severity, description, published 
                FROM cves 
                ORDER BY base_score DESC, published DESC
                LIMIT ?""", (limit,))
    
    rows = c.fetchall()
    conn.close()
    
    cves = []
    for row in rows:
        cves.append({
            "cve_id": row[0],
            "base_score": row[1],
            "severity": row[2],
            "description": row[3][:200],
            "published": row[4]
        })
    
    return cves

if __name__ == "__main__":
    save_openemr_cves()