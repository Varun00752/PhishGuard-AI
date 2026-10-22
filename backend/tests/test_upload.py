import io
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_upload_valid_eml():
    eml_content = (
        b"From: Security Support <support@suspicious-bank-login.com>\r\n"
        b"Subject: Action Required: Your Account Has Been Locked\r\n"
        b"To: victim@example.com\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Dear user,\nYour account is locked. Please click http://192.168.1.1/login immediately."
    )
    files = {"file": ("test_alert.eml", io.BytesIO(eml_content), "message/rfc822")}
    response = client.post("/api/upload-email", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["sender"] == "Security Support <support@suspicious-bank-login.com>"
    assert data["subject"] == "Action Required: Your Account Has Been Locked"
    assert "http://192.168.1.1/login" in data["body"]
    assert data["filename"] == "test_alert.eml"


def test_upload_html_eml():
    eml_content = (
        b"From: HR Department <hr@company.com>\r\n"
        b"Subject: Open Enrollment\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<p>Please review our <a href='https://benefits.company.com'>benefits portal</a>.</p>"
    )
    files = {"file": ("benefits.eml", io.BytesIO(eml_content), "message/rfc822")}
    response = client.post("/api/upload-email", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["sender"] == "HR Department <hr@company.com>"
    assert data["subject"] == "Open Enrollment"
    assert "benefits portal (https://benefits.company.com)" in data["body"]


def test_upload_empty_file():
    files = {"file": ("empty.eml", io.BytesIO(b""), "message/rfc822")}
    response = client.post("/api/upload-email", files=files)
    assert response.status_code == 422


def test_upload_snapchat_tracking_eml():
    eml = (
        b"From: Team Snapchat <no-reply@snapchat.com>\r\n"
        b"Subject: Attempted Log In\r\n"
        b"To: user@example.com\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><body>"
        b"<p>It looks like someone attempted to log in to your account.</p>"
        b"<p>Please change your password <a href='https://accounts.snapchat.com/accounts/change_password'>here</a>.</p>"
        b"<p><a href='https://j3lbpcd9.r.us-east-1.awstrack.me/L0/https:%2F%2Fsnap.com%2Fterms/1/010001a124458afc/v7CVzP=473'>Terms of Service</a></p>"
        b"</body></html>"
    )
    files = {"file": ("snapchat.eml", io.BytesIO(eml), "message/rfc822")}
    response = client.post("/api/upload-email", files=files)
    assert response.status_code == 200
    data = response.json()
    assert "https://snap.com/terms" in data["body"]
    assert "awstrack.me" not in data["body"]

    # Now verify analyze endpoint assesses this unwrapped content as Safe
    analyze_resp = client.post("/api/analyze", json={
        "sender": data["sender"],
        "subject": data["subject"],
        "body": data["body"]
    })
    assert analyze_resp.status_code == 200
    analyze_data = analyze_resp.json()
    assert analyze_data["risk_category"] == "Safe"

