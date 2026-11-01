"""Public data model of a scan report. This is the API contract."""

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class Status(StrEnum):
    """Outcome of a single check.

    ``inconclusive`` means the check could not reach a verdict (timeout, DNS
    failure, nothing to inspect). It never awards or costs points: it is left
    out of the score and reported under coverage instead.
    """

    PASS = "pass"  # noqa: S105 - a status, not a password
    WARN = "warn"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    INFO = "info"


class Category(StrEnum):
    EMAIL = "email"
    TRANSPORT = "transport"
    HEADERS = "headers"
    INFO = "info"


CATEGORY_TITLES: dict[Category, str] = {
    Category.EMAIL: "Email authentication",
    Category.TRANSPORT: "HTTPS and TLS",
    Category.HEADERS: "HTTP security headers",
    Category.INFO: "Informational",
}

Grade = Literal["A", "B", "C", "D", "F"]


class Evidence(BaseModel):
    """One observed fact behind a verdict, e.g. the DMARC record that was read."""

    label: str
    value: str


class Reference(BaseModel):
    title: str
    url: str


class CheckResult(BaseModel):
    id: str = Field(examples=["email.dmarc"])
    title: str
    category: Category
    status: Status
    weight: int = Field(description="Most points the check can award; 0 for informational checks.")
    points: float = Field(description="Points awarded: weight for pass, half for warn, else 0.")
    summary: str = Field(description="One sentence stating what was found.")
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str | None = Field(default=None, description="How to fix a warn or fail.")
    references: list[Reference] = Field(default_factory=list)
    duration_ms: int


class CategorySummary(BaseModel):
    id: Category
    title: str
    score: int | None = Field(description="0-100 over completed scored checks; null if none.")
    points: float
    possible: int = Field(description="Sum of weights of completed scored checks.")


class Coverage(BaseModel):
    scored: int = Field(description="Scored checks that reached a verdict (pass, warn or fail).")
    inconclusive: int = Field(description="Scored checks that could not reach a verdict.")
    total: int = Field(description="All scored checks (weight > 0).")


class ScanReport(BaseModel):
    domain: str
    scanned_at: datetime
    duration_ms: int
    score: int | None = Field(
        description="0-100 over completed scored checks; null when too few checks completed."
    )
    grade: Grade | None
    coverage: Coverage
    categories: list[CategorySummary]
    checks: list[CheckResult]
    scanner_version: str
    methodology_version: str
