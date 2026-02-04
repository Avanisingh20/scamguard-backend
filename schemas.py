from pydantic import BaseModel
from typing import List

class ExtractedEntities(BaseModel):
    upi_ids: List[str]
    phishing_links: List[str]
    otps: List[str]

class HoneypotResponse(BaseModel):
    scam_detected: bool
    risk_level: str
    confidence: float
    tactics: List[str]
    confidence_factors: List[str]
    agent_reply: str
    extracted_entities: ExtractedEntities

class InputMessage(BaseModel):
    input_message: str