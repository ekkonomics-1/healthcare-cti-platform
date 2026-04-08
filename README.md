# Healthcare CTI Platform

Intelligent Threat Scoring & Prioritization System for Healthcare Cybersecurity

## Overview

This platform collects threat intelligence from multiple sources, scores IOCs using a Random Forest ML model, and provides a dashboard for CTI analysts.

## Features

- **CTI Collector**: Fetches IOCs from OTX AlienVault, Feodo Tracker, URLhaus
- **ML Scoring**: Random Forest model classifies threats as Critical/High/Medium/Low
- **Dashboard**: Real-time KPIs and IOC feed
- **Shuffle Integration**: HTTP API for SOAR automation

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure API Key

The OTX API key is already set in `config/config.py`. To change it:

```python
# config/config.py
OTX_API_KEY = "your-otx-api-key"
```

### 3. Run Collector

```bash
python collector/fetch_iocs.py
```

### 4. Train Model

```bash
python model/train.py
```

### 5. Start API

```bash
python api/main.py
```

### 6. Open Dashboard

Navigate to: `http://localhost:8000`

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/score` | POST | Score an IOC |
| `/iocs` | GET | List all IOCs |
| `/kpis` | GET | Get dashboard KPIs |
| `/collect` | POST | Trigger IOC collection |

## Example Usage

### Score an IOC

```bash
curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -d '{"ioc": "185.220.101.45", "ioc_type": "ip", "confidence": 85, "is_c2": 1}'
```

Response:
```json
{
  "ioc": "185.220.101.45",
  "label": "Critical",
  "confidence": 0.91,
  "explanation": "Critical priority: Tagged as C2/botnet, High source confidence (85%)"
}
```

## Shuffle Integration

Add HTTP action in Shuffle workflow:

```
URL: http://<your-server>:8000/score
Method: POST
Body: {"ioc": "{{source_ip}}", "ioc_type": "ip", "confidence": 50}
```

## Architecture

```
External Sources (OTX, Feodo, URLhaus)
           ↓
    CTI Collector
           ↓
    SQLite Database
           ↓
    Feature Extractor → ML Model
           ↓
    FastAPI Backend
           ↓
    Dashboard + Shuffle
```

## Requirements

- Python 3.8+
- FastAPI
- scikit-learn
- requests
- pandas

## License

MIT