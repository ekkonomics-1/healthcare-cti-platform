import os

OTX_API_KEY = os.getenv("OTX_API_KEY", "66ce826a02750446511b20564e42785c4ab1e699e598122d01762df0e200ee0b")
VT_API_KEY = os.getenv("VT_API_KEY", "e4d4d6f32775ee354c6bd7bbe134f75469cccb582a1659d8572cb5ae8b4d1572")

DATABASE_PATH = "database/iocs.db"

CORTEX_ENABLED = False

HEALTHCARE_TAGS = ["healthcare", "medical", "hospital", "ransomware", "hl7", "dicom", "emr", "ehr", "fhir", "medical-device", "phi", "emr"]

THREAT_LABELS = ["Critical", "High", "Medium", "Low"]

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/urls_recent.json"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

API_HOST = "0.0.0.0"
API_PORT = 8000