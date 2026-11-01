from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from SecurityAuditor import SecurityAuditor
import json
import logging
import os
from typing import List, Dict, Any

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Web Risk Audit API",
    description="API for performing passive security audits on domains.",
    version="2.1.0"
)

# Configure CORS middleware (ALLOWED_ORIGINS is a comma-separated list)
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,https://webriskaudit.com").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# ===========================
# Pydantic Models
# ===========================

class ScanRequest(BaseModel):
    domain: str

class CategoryScoreDetail(BaseModel):
    score: int
    max: int
    percentage: float
    risk_level: str
    tests: List[str] = []

class ScanResponse(BaseModel):
    domain: str
    score: int
    risk_level: str

    # Email & Reputation
    spf_status: bool
    dkim_status: bool
    dmarc_status: bool
    blacklist_status: bool

    # Server Security
    waf_status: bool
    ssl_status: bool
    server_leak: bool
    security_headers_score: int

    # Compliance
    compliance_risk: bool

    # Category scores
    email_security: CategoryScoreDetail
    server_security: CategoryScoreDetail
    compliance: CategoryScoreDetail

# ===========================
# Helper Functions
# ===========================

def calculate_risk_level(score: int) -> str:
    if score >= 80:
        return "SECURE"
    elif score >= 50:
        return "MODERATE"
    else:
        return "CRITICAL"

def map_category(category: dict) -> dict:
    """Maps one SecurityAuditor category to CategoryScoreDetail format."""
    score = category.get("score", 0)
    max_score = category.get("max", 0)
    percentage = (score / max_score * 100) if max_score > 0 else 0
    return {
        "score": score,
        "max": max_score,
        "percentage": round(percentage, 1),
        "risk_level": category.get("status", "CRITICAL"),
        "tests": []
    }

def map_audit_results(domain: str, raw_report: dict) -> dict:
    """
    Maps new SecurityAuditor output (simplified 3-level structure) to ScanResponse format.

    Input structure (new):
    {
        "domain": str,
        "score": int,  # normalized to 0-100
        "email_security": {"score": int, "max": int, "status": str, "details": {...}},
        "server_security": {"score": int, "max": int, "status": str, "details": {...}},
        "compliance": {"score": int, "max": int, "status": str, "details": {...}}
    }
    """
    # Extract category data
    email_sec = raw_report.get("email_security", {})
    server_sec = raw_report.get("server_security", {})
    compliance = raw_report.get("compliance", {})

    # Email details
    email_details = email_sec.get("details", {})
    spf_status = email_details.get("spf", {}).get("found", False)
    dmarc_status = email_details.get("dmarc", {}).get("found", False)
    dkim_status = email_details.get("dkim", {}).get("found", False)
    blacklist_clean = email_details.get("blacklist", {}).get("clean", False)

    # Server details
    server_details = server_sec.get("details", {})
    ssl_status = server_details.get("ssl", {}).get("valid", False)
    waf_status = server_details.get("waf", {}).get("detected", False)
    server_masked = server_details.get("server_identity", {}).get("masked", False)
    headers_count = server_details.get("security_headers", {}).get("count", 0)

    # Compliance details
    comp_details = compliance.get("details", {})
    privacy_found = comp_details.get("privacy_policy", {}).get("found", False)

    return {
        "score": raw_report.get("score", 0),
        "risk_level": calculate_risk_level(raw_report.get("score", 0)),

        # Email (note: blacklist_status True=Clean, False=Blacklisted)
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "blacklist_status": blacklist_clean,  # Maps directly (True=Clean)

        # Server (note: server_leak True=Leaking, False=Secure)
        "waf_status": waf_status,
        "ssl_status": ssl_status,
        "server_leak": not server_masked,  # Inverted: leak = NOT masked
        "security_headers_score": headers_count,

        # Compliance (note: compliance_risk True=Risk, False=Safe)
        "compliance_risk": not privacy_found,  # Inverted: risk = NOT found

        # Categories
        "categories": {
            "email_security": map_category(email_sec),
            "server_security": map_category(server_sec),
            "compliance": map_category(compliance)
        }
    }

# ===========================
# API Endpoints
# ===========================

@app.get("/")
def root():
    return {"message": "Web Risk Audit API is running"}

@app.post("/api/scan", response_model=ScanResponse)
def scan_domain(request: ScanRequest):
    """
    Scans a domain and returns the security report.
    Responds 502 with a generic message if the scan fails; details are only logged.
    """
    logger.info(f"Starting scan for domain: {request.domain}")
    cleaned_domain = request.domain.strip()

    try:
        auditor = SecurityAuditor(cleaned_domain)
        raw_report = auditor.run_audit()  # New SecurityAuditor returns dict directly
        cleaned_domain = auditor.domain # Update with normalized domain
        mapped_results = map_audit_results(cleaned_domain, raw_report)
    except Exception:
        logger.exception(f"Audit failed for {cleaned_domain}")
        raise HTTPException(status_code=502, detail="Scan failed: the domain could not be checked.")

    return ScanResponse(
        domain=cleaned_domain,
        score=mapped_results["score"],
        risk_level=mapped_results["risk_level"],
        
        spf_status=mapped_results["spf_status"],
        dkim_status=mapped_results["dkim_status"],
        dmarc_status=mapped_results["dmarc_status"],
        blacklist_status=mapped_results["blacklist_status"],
        
        waf_status=mapped_results["waf_status"],
        ssl_status=mapped_results["ssl_status"],
        server_leak=mapped_results["server_leak"],
        security_headers_score=mapped_results["security_headers_score"],
        
        compliance_risk=mapped_results["compliance_risk"],
        
        email_security=mapped_results["categories"]["email_security"],
        server_security=mapped_results["categories"]["server_security"],
        compliance=mapped_results["categories"]["compliance"]
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
