import logging
from typing import List, Dict, Any
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .models import EmailAnalyzeRequest, AnalysisResult, HealthResponse
from .analyzer.engine import analyzer_engine
from .samples import SAMPLE_EMAILS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("phishguard.api")

app = FastAPI(
    title="PhishGuard AI — Phishing Email Analyzer API",
    description="Explainable, rule-based phishing risk assessment engine and URL inspector.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration for local frontend development and tests
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"  # Allows local network testing during hackathons
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Returns the operational status of the PhishGuard AI service."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        service="phishguard-ai-backend"
    )


@app.get("/api/samples", response_model=List[Dict[str, Any]], tags=["Samples"])
async def get_sample_emails():
    """Returns curated sample emails for testing and demo evaluation."""
    return SAMPLE_EMAILS


@app.post(
    "/api/analyze",
    response_model=AnalysisResult,
    status_code=status.HTTP_200_OK,
    tags=["Analysis"]
)
async def analyze_email(payload: EmailAnalyzeRequest):
    """
    Analyzes untrusted email content for phishing signatures, deceptive patterns,
    and suspicious URLs. Returns explainable score, indicators, and recommendations.
    """
    try:
        # Validate that at least one field has text
        if not payload.sender and not payload.subject and not payload.body:
            raise HTTPException(
                status_code=422,
                detail="At least one field (sender, subject, or body) must contain text to analyze."
            )

        logger.info(
            f"Analyzing email - Sender length: {len(payload.sender)}, "
            f"Subject length: {len(payload.subject)}, Body length: {len(payload.body)}"
        )

        result = analyzer_engine.analyze(payload)
        return result

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Unexpected error during email analysis: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while analyzing the email content. Please check input formatting."
        )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Global unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error occurred."}
    )
