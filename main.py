from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from schemas import InputMessage, HoneypotResponse
import re

app = FastAPI(title="ScamGuard AI Intelligence")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def analyze_text(text: str):
    text_clean = text.replace('\n', ' ').replace('\r', ' ').lower()

    patterns = {
        "otp": r"\b\d{4,8}\b",
        "upi": r"\b[\w\.-]+@[\w]+\b",
        "url": r"https?://[^\s]+",
        "phone": r"\b[6-9]\d{9}\b"
    }

    found = {k: re.findall(v, text_clean) for k, v in patterns.items()}

    confidence = 0
    factors = []
    tactics = []

    # Authority keywords
    if any(word in text_clean for word in ["rbi","sbi","bank","kyc","police","income tax","aadhaar","pan"]):
        confidence += 25
        factors.append("Authority Impersonation")
        tactics.append("Authority Abuse")

    # Urgency keywords
    if any(word in text_clean for word in ["urgent","blocked","immediately","deadline","penalty"]):
        confidence += 25
        factors.append("Urgency/Fear")
        tactics.append("Fear")

    # Reward keywords
    if any(word in text_clean for word in ["lottery","won","reward","gift","bonus","prize"]):
        confidence += 25
        factors.append("Reward Lure")
        tactics.append("Greed")

    # Detected entities
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
        risk = "CRITICAL"
        reply = "HIGH SCAM RISK"
    elif confidence >= 50:
        risk = "HIGH"
        reply = "Likely Scam"
    elif confidence >= 30:
        risk = "MEDIUM"
        reply = "Be Careful"
    else:
        risk = "LOW"
        reply = "Looks Safe"

    return {
        "scam_detected": confidence >= 40,
        "risk_level": risk,
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

# Main endpoint (accepts trailing slash too)
@app.post("/analyze")
@app.post("/analyze/")
def analyze_message(data: InputMessage):
    return analyze_text(data.input_message)

# Health check
@app.get("/")
def root():
    return {"status": "API running"}
