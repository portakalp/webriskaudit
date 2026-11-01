from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base

class Lead(Base):
    """
    Lead model to track unique contacts.
    Scan results now stored in separate 'scans' table.

    Status Flow:
    1. "raw_lead" - User submitted form, scan starting
    2. "scanned" - Mini-report shown to user
    3. "full_report_requested" - User clicked Approve (HOT LEAD!)
    """
    __tablename__ = "leads"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)

    # Lead status tracking
    status = Column(
        String,
        default="raw_lead",
        nullable=False
    )  # Options: "raw_lead", "scanned", "full_report_requested"

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationship to scans
    scans = relationship("Scan", back_populates="lead", foreign_keys="[Scan.lead_id]")

    def __repr__(self):
        return f"<Lead(id={self.id}, email='{self.email}', status='{self.status}')>"


class Scan(Base):
    """
    Audit history table. Stores every security scan performed.
    One lead can have multiple scans.
    """
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    lead_id = Column(Integer, ForeignKey("leads.id"), nullable=False, index=True)
    domain = Column(String, nullable=False, index=True)

    # Audit results
    score = Column(Integer, nullable=True)

    # Email Authentication & Reputation
    spf_status = Column(Boolean, default=False)        # SPF record present
    dkim_status = Column(Boolean, default=False)       # DKIM configured (future)
    dmarc_status = Column(Boolean, default=False)
    blacklist_status = Column(Boolean, default=True)   # True=Clean, False=Blacklisted

    # Server Security
    waf_status = Column(Boolean, default=False)
    ssl_status = Column(Boolean, default=False)        # SSL valid & not expiring soon
    server_leak = Column(Boolean, default=True)        # True=Leaking info, False=Secure
    security_headers_score = Column(Integer, default=0) # 0-4 count of missing headers

    # Compliance
    compliance_risk = Column(Boolean, default=False)
    cookie_consent_detected = Column(Boolean, default=False)
    data_leak_safe = Column(Boolean, default=True)  # True=Safe, False=Leaks detected

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationship
    lead = relationship("Lead", back_populates="scans")

    def __repr__(self):
        return f"<Scan(id={self.id}, lead_id={self.lead_id}, domain='{self.domain}', score={self.score})>"
