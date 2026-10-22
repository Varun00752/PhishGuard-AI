import sys
from pathlib import Path

# Add backend to Python path
backend_path = Path(__file__).resolve().parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.main import app

# Expose app for Vercel Serverless Function
handler = app
