from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from SecurityAuditor import SecurityAuditor
import json
import logging
from typing import List, Dict, Optional, Any

# Import database components
# We wrap these in try-except to prevent import errors from crashing the app immediately
# though in a real scenario we'd want to know if DB is missing.
try:
    from database import engine, get_db, Base
    from models import Lead, Scan
    # Create database tables on startup
    Base.metadata.create_all(bind=engine)
    DB_AVAILABLE = True
except ImportError:
    DB_AVAILABLE = False
    print("⚠️ Database modules not found. Running in no-DB mode.")
except Exception as e:
    DB_AVAILABLE = False
    print(f"⚠️ Database initialization failed: {str(e)}. Running in no-DB mode.")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Web Risk Audit API",
    description="API for performing passive security audits on domains.",
    version="2.1.0"
)

# Configure CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# ===========================
# Pydantic Models
# ===========================

class ScanRequest(BaseModel):
    email: str
    domain: str

class CategoryScoreDetail(BaseModel):
    score: int
    max: int
    percentage: float
    risk_level: str
    tests: List[str] = []

class ScanResponse(BaseModel):
    lead_id: int = 0
    scan_id: int = 0
    domain: str
    score: int
    risk_level: str
    error: Optional[str] = None

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
    cookie_consent_detected: bool
    data_leak_safe: bool

    # Category scores
    email_security: CategoryScoreDetail
    server_security: CategoryScoreDetail
    compliance: CategoryScoreDetail

class FullReportRequest(BaseModel):
    lead_id: int

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

def get_default_categories():
    return {
        "email_security": {"score": 0, "max": 35, "percentage": 0.0, "risk_level": "CRITICAL", "tests": []},
        "server_security": {"score": 0, "max": 50, "percentage": 0.0, "risk_level": "CRITICAL", "tests": []},
        "compliance": {"score": 0, "max": 15, "percentage": 0.0, "risk_level": "CRITICAL", "tests": []}
    }

def map_audit_results(domain: str, raw_report: dict) -> dict:
    """
    Maps new SecurityAuditor output (simplified 3-level structure) to ScanResponse format.

    Input structure (new):
    {
        "domain": str,
        "score": int,
        "email_security": {"score": int, "status": str, "details": {...}},
        "server_security": {"score": int, "status": str, "details": {...}},
        "compliance": {"score": int, "status": str, "details": {...}}
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
    cookie_consent = comp_details.get("cookie_consent", {}).get("assumed", False)

    # Calculate category percentages
    email_percentage = (email_sec.get("score", 0) / 35 * 100) if 35 > 0 else 0
    server_percentage = (server_sec.get("score", 0) / 50 * 100) if 50 > 0 else 0
    compliance_percentage = (compliance.get("score", 0) / 15 * 100) if 15 > 0 else 0

    return {
        "score": raw_report.get("score", 0),
        "risk_level": calculate_risk_level(raw_report.get("score", 0)),

        # Email (note: blacklist_status in DB: True=Clean, False=Blacklisted)
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "dmarc_status": dmarc_status,
        "blacklist_status": blacklist_clean,  # Maps directly (True=Clean)

        # Server (note: server_leak in DB: True=Leaking, False=Secure)
        "waf_status": waf_status,
        "ssl_status": ssl_status,
        "server_leak": not server_masked,  # Inverted: leak = NOT masked
        "security_headers_score": headers_count,

        # Compliance (note: compliance_risk in DB: True=Risk, False=Safe)
        "compliance_risk": not privacy_found,  # Inverted: risk = NOT found
        "cookie_consent_detected": cookie_consent,
        "data_leak_safe": True,  # Always true in new version

        # Categories
        "categories": {
            "email_security": {
                "score": email_sec.get("score", 0),
                "max": 35,
                "percentage": round(email_percentage, 1),
                "risk_level": email_sec.get("status", "CRITICAL"),
                "tests": []
            },
            "server_security": {
                "score": server_sec.get("score", 0),
                "max": 50,
                "percentage": round(server_percentage, 1),
                "risk_level": server_sec.get("status", "CRITICAL"),
                "tests": []
            },
            "compliance": {
                "score": compliance.get("score", 0),
                "max": 15,
                "percentage": round(compliance_percentage, 1),
                "risk_level": compliance.get("status", "CRITICAL"),
                "tests": []
            }
        }
    }

def get_fallback_response(domain: str, error_msg: str) -> ScanResponse:
    defaults = get_default_categories()
    return ScanResponse(
        domain=domain,
        score=0,
        risk_level="CRITICAL",
        error=error_msg,
        spf_status=False,
        dkim_status=False,
        dmarc_status=False,
        blacklist_status=False,
        waf_status=False,
        ssl_status=False,
        server_leak=False,
        security_headers_score=0,
        compliance_risk=True,
        cookie_consent_detected=False,
        data_leak_safe=False,
        email_security=defaults["email_security"],
        server_security=defaults["server_security"],
        compliance=defaults["compliance"]
    )

# ===========================
# API Endpoints
# ===========================

@app.get("/")
def root():
    return {"message": "Web Risk Audit API is running"}

@app.post("/api/scan", response_model=ScanResponse)
def scan_domain(request: ScanRequest, db: Session = Depends(get_db) if DB_AVAILABLE else None):
    """
    Scans a domain and returns the security report.
    Handles ALL errors gracefully by returning a fallback 200 OK response with error details.
    """
    logger.info(f"Starting scan for domain: {request.domain}")
    cleaned_domain = request.domain.strip()
    
    # Initialize these for the DB block
    mapped_results = {}
    
    # --- STEP 1: PERFORM AUDIT ---
    try:
        auditor = SecurityAuditor(cleaned_domain)
        raw_report = auditor.run_audit()  # New SecurityAuditor returns dict directly
        cleaned_domain = auditor.domain # Update with normalized domain
        mapped_results = map_audit_results(cleaned_domain, raw_report)
    except Exception as e:
        logger.error(f"Audit failed for {cleaned_domain}: {e}")
        # Return graceful error response immediately if audit fails completely
        return get_fallback_response(cleaned_domain, str(e))

    # --- STEP 2: SAVE TO DATABASE (Optional/Safe) ---
    lead_id = 0
    scan_id = 0
    
    if DB_AVAILABLE and db:
        try:
            # Check/Create Lead
            lead = db.query(Lead).filter(Lead.email == request.email).first()
            if not lead:
                lead = Lead(email=request.email, status="raw_lead")
                db.add(lead)
                db.commit()
                db.refresh(lead)
            
            lead_id = lead.id

            # Create Scan Record
            new_scan = Scan(
                lead_id=lead.id,
                domain=cleaned_domain,
                score=mapped_results["score"],
                spf_status=mapped_results["spf_status"],
                dkim_status=mapped_results["dkim_status"],
                dmarc_status=mapped_results["dmarc_status"],
                blacklist_status=mapped_results["blacklist_status"],
                waf_status=mapped_results["waf_status"],
                ssl_status=mapped_results["ssl_status"],
                server_leak=mapped_results["server_leak"],
                security_headers_score=mapped_results["security_headers_score"],
                compliance_risk=mapped_results["compliance_risk"],
                cookie_consent_detected=mapped_results["cookie_consent_detected"],
                data_leak_safe=mapped_results["data_leak_safe"]
            )
            db.add(new_scan)
            db.commit()
            db.refresh(new_scan)
            scan_id = new_scan.id
            
            # Update lead status
            lead.status = "scanned"
            db.commit()
            
        except Exception as e:
            logger.error(f"Database operation failed: {e}")
            # Do NOT raise HTTPException. Log and continue.
            # We just leave lead_id and scan_id as 0.

    # --- STEP 3: RETURN RESPONSE ---
    return ScanResponse(
        lead_id=lead_id,
        scan_id=scan_id,
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
        cookie_consent_detected=mapped_results["cookie_consent_detected"],
        data_leak_safe=mapped_results["data_leak_safe"],
        
        email_security=mapped_results["categories"]["email_security"],
        server_security=mapped_results["categories"]["server_security"],
        compliance=mapped_results["categories"]["compliance"]
    )

@app.post("/api/request-full-report")
def request_full_report(request: FullReportRequest, db: Session = Depends(get_db) if DB_AVAILABLE else None):
    try:
        if DB_AVAILABLE and db:
            lead = db.query(Lead).filter(Lead.id == request.lead_id).first()
            if lead:
                lead.status = "full_report_requested"
                db.commit()
        return {"message": "Report requested successfully"}
    except Exception as e:
        logger.error(f"Full report request failed: {e}")
        return {"message": "Request received (with internal warning)"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
