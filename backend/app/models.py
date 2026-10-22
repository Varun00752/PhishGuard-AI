from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class EmailAnalyzeRequest(BaseModel):
    sender: str = Field(
        default="",
        max_length=500,
        description="The email sender header or address (e.g., 'IT Support <support@company.com>')"
    )
    subject: str = Field(
        default="",
        max_length=1000,
        description="The email subject line"
    )
    body: str = Field(
        default="",
        max_length=100000,
        description="The raw text or body of the email (untrusted content)"
    )

    @field_validator("sender", "subject", "body", mode="before")
    @classmethod
    def strip_and_normalize(cls, v: Optional[str]) -> str:
        if v is None:
            return ""
        return str(v).strip()


class Indicator(BaseModel):
    id: str
    title: str
    category: str  # urgency, credentials, financial, impersonation, sender, links, general
    severity: str  # low, medium, high, critical
    score_delta: int
    matched_terms: List[str] = Field(default_factory=list)
    explanation: str


class ExtractedURL(BaseModel):
    url: str
    domain: str
    is_suspicious: bool
    flags: List[str] = Field(default_factory=list)
    risk_level: str  # safe, suspicious, high


class EmailStats(BaseModel):
    char_count: int
    word_count: int
    url_count: int
    suspicious_url_count: int


class AnalysisResult(BaseModel):
    score: int = Field(ge=0, le=100, description="Normalized phishing risk score between 0 and 100")
    risk_category: str = Field(description="'Safe', 'Suspicious', or 'Phishing'")
    summary: str
    indicators: List[Indicator]
    extracted_urls: List[ExtractedURL]
    recommendations: List[str]
    stats: EmailStats
    disclaimer: str
    analyzed_at: str


class HealthResponse(BaseModel):
    status: str
    version: str
    service: str
