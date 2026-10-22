from datetime import datetime, timezone
from typing import List
from ..models import (
    EmailAnalyzeRequest,
    AnalysisResult,
    Indicator,
    ExtractedURL,
    EmailStats
)
from .url_extractor import extract_and_analyze_urls
from .recommendations import generate_recommendations
from .rules import (
    check_urgency_threats,
    check_credentials,
    check_financial,
    check_impersonation,
    check_sender_inconsistencies
)

DISCLAIMER_TEXT = (
    "PhishGuard AI provides explainable heuristic risk scoring based on static text analysis and URL inspection. "
    "It operates in a secure sandbox: it does NOT visit or execute URLs, download attachments, or query external AI services. "
    "SPF, DKIM, and DMARC authentication checks were not performed (raw email transport headers are required for cryptographic authentication). "
    "This analysis is a heuristic estimate to aid human decision-making, not an absolute security guarantee."
)


class PhishingAnalyzer:
    """
    Modular, deterministic, explainable rule-based phishing analyzer.
    """

    def analyze(self, request: EmailAnalyzeRequest) -> AnalysisResult:
        sender = request.sender.strip()
        subject = request.subject.strip()
        body = request.body.strip()

        combined_text = f"{subject}\n{body}"
        extracted_urls: List[ExtractedURL] = extract_and_analyze_urls(combined_text)

        indicators: List[Indicator] = []

        # 1. URL-derived indicators
        suspicious_urls = [u for u in extracted_urls if u.is_suspicious]
        if suspicious_urls:
            url_flags = []
            for u in suspicious_urls:
                for f in u.flags:
                    if f not in url_flags:
                        url_flags.append(f)

            severity = "critical" if any(u.risk_level == "high" for u in suspicious_urls) else "high"
            delta = min(40, 20 + (len(suspicious_urls) * 8))

            indicators.append(Indicator(
                id="IND_SUSPICIOUS_URLS",
                title="Suspicious or Deceptive Web Links",
                category="links",
                severity=severity,
                score_delta=delta,
                matched_terms=[u.url for u in suspicious_urls[:3]],
                explanation=(
                    f"Found {len(suspicious_urls)} suspicious link(s) exhibiting evasion or spoofing techniques: "
                    f"{'; '.join(url_flags[:3])}. Attackers use shortened, IP-hosted, or lookalike links to route victims to malicious credential-harvesting portals."
                )
            ))

        # 2. Urgency and threats
        indicators.extend(check_urgency_threats(subject, body))

        # 3. Credential harvesting prompts
        indicators.extend(check_credentials(subject, body))

        # 4. Financial / payment / BEC demands
        indicators.extend(check_financial(subject, body))

        # 5. Impersonation of authority / brands
        indicators.extend(check_impersonation(subject, body))

        # 6. Sender inconsistencies and spoofing
        if sender:
            indicators.extend(check_sender_inconsistencies(sender, subject, body))

        # Scoring calculation
        raw_score = sum(ind.score_delta for ind in indicators)

        # Trifecta synergy bonus: if urgency + credentials + (suspicious url OR sender spoof) are all present
        categories_detected = {ind.category for ind in indicators}
        if "urgency" in categories_detected and "credentials" in categories_detected and ("links" in categories_detected or "sender" in categories_detected):
            raw_score += 15

        # Normalize score between 0 and 100
        score = max(0, min(100, raw_score))

        # Determine risk category
        if score >= 70:
            risk_category = "Phishing"
        elif score >= 30:
            risk_category = "Suspicious"
        else:
            risk_category = "Safe"

        # Generate human-readable summary
        summary = self._generate_summary(score, risk_category, indicators, extracted_urls)

        # Generate targeted recommendations
        recommendations = generate_recommendations(score, indicators, extracted_urls)

        stats = EmailStats(
            char_count=len(body) + len(subject),
            word_count=len(body.split()) + len(subject.split()),
            url_count=len(extracted_urls),
            suspicious_url_count=len(suspicious_urls)
        )

        return AnalysisResult(
            score=score,
            risk_category=risk_category,
            summary=summary,
            indicators=indicators,
            extracted_urls=extracted_urls,
            recommendations=recommendations,
            stats=stats,
            disclaimer=DISCLAIMER_TEXT,
            analyzed_at=datetime.now(timezone.utc).isoformat()
        )

    def _generate_summary(
        self,
        score: int,
        category: str,
        indicators: List[Indicator],
        urls: List[ExtractedURL]
    ) -> str:
        if not indicators and not urls:
            return "No suspicious indicators detected. The text and sender details appear typical of routine communication."

        if category == "Phishing":
            critical_count = sum(1 for i in indicators if i.severity in ("critical", "high"))
            top_titles = [i.title for i in indicators[:3]]
            return (
                f"High Phishing Probability (Score: {score}/100). The email exhibits {len(indicators)} risk factor(s) "
                f"({critical_count} critical/high), including {', '.join(top_titles)}. "
                "Strong indication of a targeted credential harvesting or social engineering attempt. Do not engage."
            )

        if category == "Suspicious":
            top_titles = [i.title for i in indicators[:2]]
            return (
                f"Suspicious Content Detected (Score: {score}/100). The email triggered {len(indicators)} warning flag(s), "
                f"notably {', '.join(top_titles)}. "
                "While not definitively confirmed as malicious, independent verification of the sender and request is recommended."
            )

        # Safe
        return (
            f"Low Risk (Score: {score}/100). Minimal warning flags were identified. "
            "The message does not display obvious phishing lures or credential-harvesting patterns, but standard email hygiene applies."
        )


analyzer_engine = PhishingAnalyzer()
