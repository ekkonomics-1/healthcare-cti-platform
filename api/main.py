from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
@app.get("/index")
def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/dashboard", status_code=302)

@app.get("/dashboard")
@app.get("/dashboard.html")
def dashboard():
    try:
        with open("dashboard/index.html", "r", encoding="utf-8") as f:
            from fastapi.responses import HTMLResponse
            return HTMLResponse(f.read())
    except Exception as e:
        return f"Dashboard not found: {e}"

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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=API_HOST, port=API_PORT)