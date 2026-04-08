from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import json
from datetime import datetime, timedelta
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model.predict import predict as ml_predict, load_model as load_ml_model
from collector.fetch_iocs import collect_all_iocs
from config.config import DATABASE_PATH, THREAT_LABELS, API_HOST, API_PORT

app = FastAPI(title="Healthcare CTI Scoring API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model_loaded = False

class IOCRequest(BaseModel):
    ioc: str
    ioc_type: str = "ip"
    confidence: int = 50
    is_healthcare: int = 0
    is_c2: int = 0

class IOCResponse(BaseModel):
    ioc: str
    label: str
    confidence: float
    features: dict
    explanation: str

class KPIResponse(BaseModel):
    total_today: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    healthcare_related: int
    avg_confidence: float

@app.on_event("startup")
async def startup_event():
    global model_loaded
    model_loaded = load_ml_model() is not None

@app.get("/")
def root():
    return {"message": "Healthcare CTI Platform", "version": "2.0.0", "dashboard": "/dashboard"}

@app.get("/dashboard")
def dashboard():
    try:
        with open("dashboard/index.html", "r", encoding="utf-8") as f:
            content = f.read()
        return Response(content, media_type="text/html")
    except Exception as e:
        return Response(f"Error loading dashboard: {e}", media_type="text/plain", status_code=500)

@app.get("/favicon.ico")
def favicon():
    return ""

@app.post("/score", response_model=IOCResponse)
def score_ioc(request: IOCRequest):
    if not model_loaded:
        raise HTTPException(status_code=503, detail="ML model not loaded")
    
    result = ml_predict(
        request.ioc,
        request.ioc_type,
        request.confidence,
        age_hours=0,
        is_healthcare=request.is_healthcare,
        is_c2=request.is_c2,
        source_count=1
    )
    
    return IOCResponse(**result)

@app.get("/iocs", response_model=List[dict])
def get_iocs(limit: int = 100, min_label: Optional[str] = None):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    if min_label:
        label_priority = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
        min_priority = label_priority.get(min_label, 0)
        c.execute(f"""SELECT ioc, ioc_type, source, tags, confidence, is_healthcare, is_c2, first_seen, last_seen
                     FROM iocs 
                     ORDER BY confidence DESC, last_seen DESC 
                     LIMIT {limit}""")
    else:
        c.execute("""SELECT ioc, ioc_type, source, tags, confidence, is_healthcare, is_c2, first_seen, last_seen
                     FROM iocs 
                     ORDER BY confidence DESC, last_seen DESC 
                     LIMIT ?""", (limit,))
    
    rows = c.fetchall()
    conn.close()
    
    iocs = []
    for row in rows:
        ioc, ioc_type, source, tags_json, confidence, is_healthcare, is_c2, first_seen, last_seen = row
        
        try:
            tags = json.loads(tags_json) if tags_json else []
        except:
            tags = []
        
        label = "Low"
        if is_c2:
            label = "Critical"
        elif is_healthcare or confidence >= 80:
            label = "High"
        elif confidence >= 60:
            label = "Medium"
        
        iocs.append({
            "ioc": ioc,
            "ioc_type": ioc_type,
            "source": source,
            "tags": tags,
            "confidence": confidence,
            "is_healthcare": is_healthcare,
            "is_c2": is_c2,
            "label": label,
            "first_seen": first_seen,
            "last_seen": last_seen
        })
    
    if min_label:
        label_priority = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
        min_p = label_priority.get(min_label, 0)
        filtered = [i for i in iocs if label_priority.get(i["label"], 0) >= min_p]
        return filtered
    
    return iocs

@app.get("/kpis", response_model=KPIResponse)
def get_kpis():
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    
    today = datetime.now().date().isoformat()
    
    c.execute("SELECT COUNT(*) FROM iocs WHERE DATE(first_seen) = ?", (today,))
    total_today = c.fetchone()[0] or 0
    
    c.execute("""SELECT 
                SUM(CASE WHEN is_c2 = 1 THEN 1 ELSE 0 END),
                SUM(CASE WHEN is_c2 = 0 AND (confidence >= 70 OR is_healthcare = 1) THEN 1 ELSE 0 END),
                SUM(CASE WHEN is_c2 = 0 AND confidence >= 40 AND confidence < 70 AND is_healthcare = 0 THEN 1 ELSE 0 END),
                SUM(CASE WHEN is_c2 = 0 AND confidence < 40 THEN 1 ELSE 0 END),
                SUM(CASE WHEN is_healthcare = 1 THEN 1 ELSE 0 END),
                AVG(confidence)
                FROM iocs WHERE DATE(first_seen) = ?""", (today,))
    
    row = c.fetchone()
    conn.close()
    
    critical = row[0] or 0
    high = row[1] or 0
    medium = row[2] or 0
    low = row[3] or 0
    healthcare = row[4] or 0
    avg_conf = row[5] or 0
    
    return KPIResponse(
        total_today=total_today,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        healthcare_related=healthcare,
        avg_confidence=round(avg_conf, 1)
    )

@app.post("/collect")
def trigger_collect():
    try:
        iocs = collect_all_iocs()
        return {"status": "success", "collected": len(iocs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/enrich/vt")
def trigger_vt_enrich():
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from sources.virustotal import enrich_all_iocs
        result = enrich_all_iocs()
        return {"status": "success", "enriched": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/cve/openemr", response_model=dict)
def get_openemr_cves(limit: int = 10):
    try:
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from sources.nvd import get_recent_cves
        cves = get_recent_cves(limit)
        return {"cves": cves, "count": len(cves)}
    except Exception as e:
        return {"cves": [], "error": str(e)}

@app.get("/health/threats")
def get_healthcare_threats(limit: int = 50):
    conn = sqlite3.connect(DATABASE_PATH)
    c = conn.cursor()
    c.execute("""SELECT ioc, ioc_type, source, tags, confidence, is_healthcare, malware_family 
                FROM iocs WHERE is_healthcare = 1 OR is_c2 = 1 OR is_medical_device = 1
                ORDER BY confidence DESC LIMIT ?""", (limit,))
    rows = c.fetchall()
    conn.close()
    threats = []
    for row in rows:
        threats.append({
            "ioc": row[0], "type": row[1], "source": row[2], 
            "tags": row[3], "confidence": row[4], 
            "is_healthcare": row[5], "malware_family": row[6]
        })
    return {"threats": threats, "count": len(threats)}

@app.get("/mitre/healthcare")
def get_mitre_healthcare():
    mitre_mapping = {
        "T1486": {"name": " Ransomware", "tactic": "Impact", "healthcare_focus": "Critical"},
        "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "healthcare_focus": "High"},
        "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "healthcare_focus": "High"},
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "healthcare_focus": "Medium"},
        "T1204": {"name": "User Execution", "tactic": "Execution", "healthcare_focus": "High"},
        "T1566": {"name": "Phishing", "tactic": "Initial Access", "healthcare_focus": "High"},
        "T1133": {"name": "External Remote Services", "tactic": "Initial Access", "healthcare_focus": "Medium"},
        "T1005": {"name": "Data from Local System", "tactic": "Collection", "healthcare_focus": "Critical"},
        "T1042": {"name": "Link Targeting", "tactic": "Command And Control", "healthcare_focus": "Medium"}
    }
    return {"mitre_healthcare": mitre_mapping, "source": "MITRE ATT&CK for Healthcare"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)