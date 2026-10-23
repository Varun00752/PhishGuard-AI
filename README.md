# Phishguard 🛡️ — Phishing Email Analyzer & Risk Engine

**Phishguard** is an explainable, rule-based phishing risk assessment engine and URL inspector with an interactive modern web interface.

---

## ✨ Features

- **Unified Single-Origin Deployment**: Serves both the interactive React/Tailwind frontend and the FastAPI REST backend from a single port (`http://localhost:8000`).
- **Drag-and-Drop Email Upload**: Drag and drop raw `.eml` files downloaded directly from **Gmail** (*"Download message"*) or plaintext emails.
- **Smart MIME & Redirect Unwrapping**:
  - Automatically parses `From`, `Subject`, and body text (plain text and HTML).
  - Unwraps known cloud email delivery click-tracking redirects (e.g. AWS SES `awstrack.me`) into their authentic destination URLs.
  - Cleans HTML markup and table padding into readable text.
- **Explainable Multi-Vector Scoring**:
  - **Urgency & Threat Analysis**: Flags artificial deadlines, threats of suspension, and coercive fear appeals.
  - **Credential Harvesting**: Detects password resets, account verification, and fake login requests.
  - **Static URL Inspection**: Detects raw IP hosts, suspicious TLDs, excessive subdomains, brand typosquatting, and sensitive path keywords without executing dangerous links.
  - **Financial & BEC Scams**: Flags urgent wire transfers, gift card solicitations, and fake overdue invoices.
- **Interactive API Documentation**: Explore endpoints via Swagger UI at `/docs`.

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- (Optional for development) Node.js 18+

### 2. Setup & Installation
```bash
# Clone the repository
git clone https://github.com/Varun00752/PhishGuard-AI.git
cd PhishGuard-AI

# Install backend dependencies
cd backend
pip install -r requirements.txt
```

### 3. Run the Application
From the `backend` directory:
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Open your browser at **`http://localhost:8000`** to access the complete application!

### 4. Running Backend Tests
```bash
pytest
```

---

## 🛠️ Architecture

- **Backend**: FastAPI, Pydantic v2, Python `email` module, Pytest.
- **Frontend**: React 18, TypeScript, Tailwind CSS, Lucide Icons, Vite.
- **Detection Engine**: Rule-based heuristic pattern matching, domain reputation inspection, and explainable score breakdown.

---

## 📄 License
MIT License.
