import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"
    assert "service" in data


def test_samples_endpoint():
    response = client.get("/api/samples")
    assert response.status_code == 200
    samples = response.json()
    assert isinstance(samples, list)
    assert len(samples) >= 4
    for sample in samples:
        assert "id" in sample
        assert "label" in sample
        assert "type" in sample
        assert "sender" in sample
        assert "subject" in sample
        assert "body" in sample


def test_analyze_endpoint_phishing():
    payload = {
        "sender": "Microsoft Security Alert <alert@security-center-update92.xyz>",
        "subject": "CRITICAL ALERT: Your Microsoft 365 Account Will Be Suspended",
        "body": "Your account will be suspended within 24 hours. Sign in here: http://microsoft-verify.xyz/login.php"
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_category"] == "Phishing"
    assert data["score"] >= 70
    assert "summary" in data
    assert "indicators" in data
    assert len(data["indicators"]) > 0
    assert "extracted_urls" in data
    assert len(data["extracted_urls"]) == 1
    assert "recommendations" in data
    assert "disclaimer" in data
    assert "stats" in data
    assert "analyzed_at" in data


def test_analyze_endpoint_benign():
    payload = {
        "sender": "Colleague Bob <bob@company.internal>",
        "subject": "Lunch update",
        "body": "Hey team, the team lunch today is scheduled for 12:30 PM at the cafeteria. See you there!"
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_category"] == "Safe"
    assert data["score"] < 30


def test_analyze_endpoint_empty_fields():
    payload = {
        "sender": "   ",
        "subject": "",
        "body": "  "
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
