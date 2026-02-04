from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
from schemas import InputMessage, HoneypotResponse
import re

app = FastAPI(title="ScamGuard AI Intelligence")

# Allow frontend to talk to backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------- CORE LOGIC --------
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
        factors.append("Urgency/Fear")
        tactics.append("Fear")

    reward_keywords = ["lottery","won","reward","gift","bonus"]
    if any(word in text_lower for word in reward_keywords):
        confidence += 25
        factors.append("Reward Lure")
        tactics.append("Greed")

    if found["otp"]:
        confidence += 35
        factors.append("OTP Detected")

    if found["upi"]:
        confidence += 15
        factors.append("UPI Detected")

    if found["url"]:
        confidence += 20
        factors.append("Phishing Link")

    confidence = min(confidence, 100)

    if confidence >= 80:
        risk_level = "CRITICAL"
        reply = "⚠️ HIGH SCAM RISK"
    elif confidence >= 50:
        risk_level = "HIGH"
        reply = "🚩 Likely Scam"
    elif confidence >= 30:
        risk_level = "MEDIUM"
        reply = "Be Careful"
    else:
        risk_level = "LOW"
        reply = "Looks Safe"

    return {
        "scam_detected": confidence >= 40,
        "risk_level": risk_level,
        "confidence": float(confidence),
        "tactics": list(set(tactics)),
        "confidence_factors": factors,
        "agent_reply": reply,
        "extracted_entities": {
            "upi_ids": found["upi"],
            "phishing_links": found["url"],
            "otps": found["otp"]
        }
    }

# -------- ENDPOINT --------
@app.post("/analyze", response_model=HoneypotResponse)
def analyze_message(data: InputMessage):
    return process_text(data.input_message)
