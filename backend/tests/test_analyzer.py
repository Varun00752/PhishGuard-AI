import pytest
from app.models import EmailAnalyzeRequest
from app.analyzer.engine import analyzer_engine
from app.analyzer.url_extractor import extract_and_analyze_urls
from app.analyzer.rules.sender import check_sender_inconsistencies


def test_phishing_email_high_risk():
    req = EmailAnalyzeRequest(
        sender="Microsoft Security Alert <alert@security-center-update92.xyz>",
        subject="CRITICAL: Your Microsoft 365 Account Will Be Suspended Within 24 Hours",
        body=(
            "Dear Valued Customer,\n\n"
            "We detected unauthorized access to your account. Your account will be suspended within 24 hours "
            "unless you verify your identity.\n\n"
            "Please click here to login and confirm your credentials:\n"
            "http://microsoft-verify-account.security-center-update92.xyz/login.php?ref=365\n\n"
            "Failure to comply will result in immediate termination.\n\n"
            "Microsoft Support"
        )
    )
    result = analyzer_engine.analyze(req)

    assert result.score >= 70
    assert result.risk_category == "Phishing"
    assert len(result.indicators) >= 3
    assert any(ind.category == "urgency" for ind in result.indicators)
    assert any(ind.category == "credentials" for ind in result.indicators)
    assert any(ind.category == "links" for ind in result.indicators)
    assert len(result.extracted_urls) >= 1
    assert result.extracted_urls[0].is_suspicious is True
    assert len(result.recommendations) >= 3


def test_executive_bec_phishing():
    req = EmailAnalyzeRequest(
        sender="Robert Vance - CEO <robert.vance.exec@gmail.com>",
        subject="Urgent: Wire Transfer / Gift Cards (In Board Meeting)",
        body=(
            "Are you at your desk right now?\n\n"
            "I am in an executive meeting and cannot take calls. I need you to handle this confidentially and urgently.\n\n"
            "Please process an immediate wire transfer of $15,000 to our supplier, or purchase 5 Apple gift cards "
            "and send me the codes.\n\n"
            "Sent from my iPhone"
        )
    )
    result = analyzer_engine.analyze(req)

    assert result.score >= 70
    assert result.risk_category == "Phishing"
    categories = {ind.category for ind in result.indicators}
    assert "financial" in categories
    assert "impersonation" in categories
    assert "sender" in categories  # freemail impersonation


def test_benign_internal_email():
    req = EmailAnalyzeRequest(
        sender="Sarah Jenkins <sjenkins@acmecorp.com>",
        subject="Team Weekly Sync - Agenda & Q3 Project Updates",
        body=(
            "Hi team,\n\n"
            "Ahead of our Friday sync at 10:00 AM, please review the Q3 roadmap updates on our internal Notion workspace:\n"
            "https://internal.acmecorp.com/wiki/q3-roadmap\n\n"
            "Key talking points:\n"
            "1. Sprint 14 retrospectives\n"
            "2. Design system migration progress\n\n"
            "Let me know if you have items to add by Thursday.\n\n"
            "Best regards,\nSarah"
        )
    )
    result = analyzer_engine.analyze(req)

    assert result.score < 30
    assert result.risk_category == "Safe"
    assert not any(ind.severity in ("critical", "high") for ind in result.indicators)
    assert len(result.extracted_urls) == 1
    assert result.extracted_urls[0].is_suspicious is False


def test_benign_newsletter():
    req = EmailAnalyzeRequest(
        sender="Security Newsletter <newsletter@cybersec-weekly.org>",
        subject="This Week in InfoSec: Industry Trends",
        body=(
            "Hello Security Enthusiasts,\n\n"
            "Welcome to this week's newsletter covering industry trends and upcoming cybersecurity webinars.\n"
            "Read more at https://cybersec-weekly.org/editions/issue-182\n\n"
            "To manage preferences: https://cybersec-weekly.org/preferences\n\n"
            "The CyberSec Weekly Team"
        )
    )
    result = analyzer_engine.analyze(req)

    assert result.score < 30
    assert result.risk_category == "Safe"


def test_suspicious_invoice_with_shortener():
    req = EmailAnalyzeRequest(
        sender="Accounts Receivable <billing@quickinvoicing-sys.top>",
        subject="OVERDUE INVOICE #INV-9042 - Immediate Payment Required",
        body=(
            "Dear Customer,\n\n"
            "Your invoice is past due. Immediate payment is required to avoid penalties.\n"
            "Download invoice statement: https://bit.ly/inv-statement-download\n\n"
            "Billing Team"
        )
    )
    result = analyzer_engine.analyze(req)

    assert result.score >= 30
    assert result.risk_category in ("Suspicious", "Phishing")
    assert any(u.is_suspicious for u in result.extracted_urls)
    assert any("URL Shortener" in flag for u in result.extracted_urls for flag in u.flags)


def test_url_extractor_ip_host():
    text = "Please access the portal at http://192.168.1.50/admin/login immediately."
    urls = extract_and_analyze_urls(text)
    assert len(urls) == 1
    assert urls[0].is_suspicious is True
    assert any("Raw IPv4 Address" in f for f in urls[0].flags)
    assert urls[0].risk_level == "high"


def test_url_extractor_brand_lookalike():
    text = "Verify your account at http://login-paypal-security-update.com/signin"
    urls = extract_and_analyze_urls(text)
    assert len(urls) == 1
    assert urls[0].is_suspicious is True
    assert any("Deceptive Brand Lookalike" in f for f in urls[0].flags)


def test_url_extractor_userinfo_trick():
    text = "Visit https://google.com@evil-attacker.com/malicious"
    urls = extract_and_analyze_urls(text)
    assert len(urls) == 1
    assert urls[0].is_suspicious is True
    assert any("Deceptive '@'" in f for f in urls[0].flags)


def test_url_extractor_suspicious_tld():
    text = "Check out the special document at http://cloud-docs-portal.xyz/view"
    urls = extract_and_analyze_urls(text)
    assert len(urls) == 1
    assert any("High-Risk TLD (.xyz)" in f for f in urls[0].flags)


def test_display_name_spoofing():
    indicators = check_sender_inconsistencies(
        "Microsoft Account Security <service@alert-notifications99.xyz>"
    )
    assert any(ind.id == "IND_DISPLAY_NAME_SPOOF" for ind in indicators)
    assert any(ind.severity == "critical" for ind in indicators)


def test_score_bounds_and_determinism():
    req = EmailAnalyzeRequest(
        sender="URGENT IT Support <admin@super-phishing-host.xyz>",
        subject="FINAL WARNING: Account suspended within 1 hour. Verify password and wire transfer now!",
        body=(
            "Dear Customer, unauthorized activity was detected. Your account will be terminated today. "
            "Click here to login and enter your password, MFA code, and credit card: "
            "http://192.168.1.10/login?redirect=paypal.com "
            "Also wire transfer $5,000 in bitcoin or buy gift cards immediately."
        )
    )
    result1 = analyzer_engine.analyze(req)
    result2 = analyzer_engine.analyze(req)

    assert 0 <= result1.score <= 100
    assert result1.score == 100
    assert result1.score == result2.score
    assert len(result1.indicators) == len(result2.indicators)
