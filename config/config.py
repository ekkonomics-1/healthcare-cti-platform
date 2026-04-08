import os

OTX_API_KEY = os.getenv("OTX_API_KEY", "66ce826a02750446511b20564e42785c4ab1e699e598122d01762df0e200ee0b")

DATABASE_PATH = "database/iocs.db"

CORTEX_ENABLED = False

HEALTHCARE_TAGS = ["healthcare", "medical", "hospital", "ransomware", "hl7", "dicom", "emr", "ehr"]

THREAT_LABELS = ["Critical", "High", "Medium", "Low"]

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

API_HOST = "0.0.0.0"
API_PORT = 8000