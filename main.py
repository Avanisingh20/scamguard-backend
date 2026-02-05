# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from schemas import InputMessage, HoneypotResponse
import re

app = FastAPI(title="ScamGuard AI Intelligence")

# ---------- CORS ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins, change in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- CORE LOGIC ----------
def process_text(text: str):
    # Clean and normalize text
    text_clean = text.replace('\n', ' ').replace('\r', ' ')
    text_lower = text_clean.lower()

    # Regex patterns
    patterns = {
        "otp": r"\b\d{4,8}\b",
        "upi": r"\b[\w\.-]+@[\w]+\b",
        "url": r"(https?://[^\s]+)",
        "phone": r"\b[6-9]\d{9}\b"
    }

    # Extract entities
    found = {k: re.findall(v, text_clean) for k, v in patterns.items()}

    # Initialize risk factors
    confidence = 0
    factors = []
    tactics = []

    # Check for authority impersonation
    authority_keywords = ["rbi","sbi","bank","kyc","police","income tax","aadhaar","pan"]
    if any(word in text_lower for word in authority_keywords):
        confidence += 25
        factors.append("Authority Impersonation")
        tactics.append("Authority Abuse")

    # Check for urgency/fear
    urgency_keywords = ["urgent","blocked","immediately","deadline","penalty"]
    if any(word in text_lower for word in urgency_keywords):
        confidence += 25
        factors.append("Urgency/Fear")
        tactics.append("Fear")

    # Check for reward lure
    reward_keywords = ["lottery","won","reward","gift","bonus","prize"]
    if any(word in text_lower for word in reward_keywords):
        confidence += 25
        factors.append("Reward Lure")
        tactics.append("Greed")

    # Add confidence for detected entities
    if found["otp"]:
        confidence += 35
        factors.append("OTP Detected")
    if found["upi"]:
        confidence += 15
        factors.append("UPI Detected")
    if found["url"]:
        confidence += 20
        factors.append("Phishing Link")

    # Cap confidence at 100
    confidence = min(confidence, 100)

    # Determine risk level
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

# ---------- ENDPOINTS ----------

# Main endpoint
@app.post("/analyze", response_model=HoneypotResponse)
def analyze_message(data: InputMessage):
    return process_text(data.input_message)

# Alias endpoint so frontend also works
@app.post("/analyze-message", response_model=HoneypotResponse)
def analyze_message_alias(data: InputMessage):
    return process_text(data.input_message)

# Health check
@app.get("/")
def root():
    return {"status": "API running"}
