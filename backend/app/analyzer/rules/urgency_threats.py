import re
from typing import List, Optional
from ...models import Indicator

URGENCY_PATTERNS = [
    (r'\b(?:urgent|urgently|immediate|immediately|action required)\b', "Immediate action requested"),
    (r'\b(?:within (?:24|48|12|1|2|3) hours?|today only|expires? in \d+)\b', "Artificial deadline imposed"),
    (r'\b(?:account (?:will be |is )?(?:suspended|terminated|deactivated|closed|locked|blocked))\b', "Threat of account suspension or closure"),
    (r'\b(?:unauthorized (?:activity|access|login|charges?)|security breach|compromised)\b', "Fear appeal regarding alleged security breach"),
    (r'\b(?:final warning|last notice|failure to comply|legal action)\b', "Severe intimidation or coercive language"),
    (r'\b(?:act now|don\'?t delay|limited time|critical alert)\b', "High-pressure urgency phrasing"),
]


def check_urgency_threats(subject: str, body: str) -> List[Indicator]:
    combined = f"{subject}\n{body}".lower()
    indicators: List[Indicator] = []

    matched_reasons = []
    matched_snippets = []

    for pattern, reason in URGENCY_PATTERNS:
        matches = re.findall(pattern, combined, re.IGNORECASE)
        if matches:
            matched_reasons.append(reason)
            # Collect unique matches for explanation
            for m in matches:
                clean_m = m.strip()
                if clean_m and clean_m not in matched_snippets:
                    matched_snippets.append(clean_m)

    if matched_reasons:
        severity = "critical" if len(matched_reasons) >= 3 or any("suspension" in r or "intimidation" in r for r in matched_reasons) else "high"
        score_delta = min(35, 15 + (len(matched_reasons) * 7))

        indicators.append(Indicator(
            id="IND_URGENCY_THREATS",
            title="High Urgency & Threat Indicators",
            category="urgency",
            severity=severity,
            score_delta=score_delta,
            matched_terms=matched_snippets[:6],
            explanation=(
                f"The email employs psychological pressure tactics ({', '.join(matched_reasons[:3])}). "
                "Attackers use artificial deadlines and threats of account disruption to bypass critical thinking and force rushed actions."
            )
        ))

    return indicators
