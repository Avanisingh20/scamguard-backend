from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from schemas import InputMessage, HoneypotResponse
import re

app = FastAPI(title="ScamGuard AI")

API_KEY = "scamguard123"

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def process_text(text: str):
    text_clean = text.replace('\n', ' ').replace('\r', ' ')
    text_lower = text_clean.lower()

    patterns = {
        "otp": r"\b\d{4,8}\b",
        "upi": r"\b[\w\.-]+@[\w]+\b",
        "url": r"(https?://[^\s]+)",
        "phone": r"\b[6-9]\d{9}\b"
    }

    found = {k: re.findall(v, text_clean) for k, v in patterns.items()}

    confidence = 0
    factors = []
    tactics = []

    authority_keywords = ["rbi","sbi","bank","kyc","police","income tax","aadhaar","pan"]
    if any(word in text_lower for word in authority_keywords):
        confidence += 25
        factors.append("Authority Impersonation")
        tactics.append("Authority Abuse")

    urgency_keywords = ["urgent","blocked","immediately","deadline","penalty"]
    if any(word in text_lower for word in urgency_keywords):
        confidence += 25
        factors.append("Urgency")

    reward_keywords = ["lottery","won","reward","gift","bonus","prize"]
    if any(word in text_lower for word in reward_keywords):
        confidence += 25
        factors.append("Reward Lure")

    if found["otp"]:
        confidence += 35
        factors.append("OTP Found")

    if found["upi"]:
        confidence += 15
        factors.append("UPI Found")

    if found["url"]:
        confidence += 20
        factors.append("Link Found")

    confidence = min(confidence, 100)

    if confidence >= 80:
        risk_level = "CRITICAL"
    elif confidence >= 50:
        risk_level = "HIGH"
    elif confidence >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "scam_detected": confidence >= 40,
        "risk_level": risk_level,
        "confidence": float(confidence),
        "tactics": list(set(tactics)),
        "confidence_factors": factors,
        "extracted_entities": {
            "upi_ids": found["upi"],
            "phishing_links": found["url"],
            "otps": found["otp"]
        }
    }

@app.post("/analyze", response_model=HoneypotResponse)
def analyze_message(data: InputMessage, x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return process_text(data.input_message)

@app.post("/analyze-message", response_model=HoneypotResponse)
def analyze_message_alias(data: InputMessage, x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return process_text(data.input_message)

@app.get("/")
def root():
    return {"status": "running"}
