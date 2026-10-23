import logging
from typing import List, Dict, Any
from pathlib import Path
from fastapi import FastAPI, HTTPException, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from .models import EmailAnalyzeRequest, AnalysisResult, HealthResponse
from .analyzer.engine import analyzer_engine
from .samples import SAMPLE_EMAILS
from .email_parser import parse_email_bytes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("phishguard.api")

app = FastAPI(
    title="Phishguard — Phishing Email Analyzer API",
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
    """Returns the operational status of the Phishguard service."""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        service="phishguard-backend"
    )


@app.get("/api/samples", response_model=List[Dict[str, Any]], tags=["Samples"])
async def get_sample_emails():
    """Returns curated sample emails for testing and demo evaluation."""
    return SAMPLE_EMAILS


@app.post("/api/upload-email", tags=["Upload"])
async def upload_email(file: UploadFile = File(...)):
    """
    Parses an uploaded .eml or raw text email message (e.g. exported from Gmail),
    extracting sender, subject, and body for phishing analysis.
    """
    try:
        content = await file.read()
        if not content:
            raise HTTPException(
                status_code=422,
                detail="The uploaded email file is empty."
            )
        parsed = parse_email_bytes(content)
        parsed["filename"] = file.filename or "uploaded_email.eml"
        return parsed
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error parsing uploaded email file: {exc}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to parse the uploaded email file. Please ensure it is a valid .eml or .txt file."
        )


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
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail}
        )
    logger.error(f"Global unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error occurred."}
    )


# Serve built frontend single-page application (SPA)
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if FRONTEND_DIST.exists():
    assets_path = FRONTEND_DIST / "assets"
    if assets_path.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_path)), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        # Do not catch unhandled API or documentation routes
        if full_path.startswith("api/") or full_path in ("docs", "redoc", "openapi.json"):
            raise HTTPException(status_code=404, detail="Endpoint not found")

        target_file = FRONTEND_DIST / full_path
        if full_path and target_file.is_file():
            return FileResponse(target_file)

        index_file = FRONTEND_DIST / "index.html"
        if index_file.is_file():
            return FileResponse(index_file)

        raise HTTPException(status_code=404, detail="Frontend build index.html not found.")
