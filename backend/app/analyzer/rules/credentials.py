import re
from typing import List
from ...models import Indicator

CREDENTIAL_PATTERNS = [
    (r'\b(?:verify|confirm|validate) your (?:identity|account|credentials|email|password|information)\b', "Direct prompt to verify account/credentials"),
    (r'\b(?:password|passcode|pin) (?:expires?|expired|reset|change|update)\b', "Password expiration or reset trigger"),
    (r'\b(?:sign[\s-]?in|log[\s-]?in) (?:to (?:restore|keep|retain|reactivate|verify)|below|here)\b', "Instruction to sign in to avoid penalty or verify"),
    (r'\b(?:enter|provide|submit) your (?:password|credentials|mfa|2fa|verification code|ssn)\b', "Explicit request for sensitive credentials"),
    (r'\b(?:update (?:your )?(?:billing|payment|security) (?:details|information|profile))\b', "Prompt to input sensitive billing or security details"),
    (r'\b(?:click here to (?:login|sign in|verify|unlock|reactivate))\b', "Call-to-action link to authenticate"),
]


def check_credentials(subject: str, body: str) -> List[Indicator]:
    combined = f"{subject}\n{body}".lower()
    indicators: List[Indicator] = []

    matched_reasons = []
    matched_snippets = []

    for pattern, reason in CREDENTIAL_PATTERNS:
        matches = re.findall(pattern, combined, re.IGNORECASE)
        if matches:
            matched_reasons.append(reason)
            for m in matches:
                clean_m = m.strip()
                if clean_m and clean_m not in matched_snippets:
                    matched_snippets.append(clean_m)

    if matched_reasons:
        severity = "critical" if any("Explicit request" in r or "sign in to avoid" in r for r in matched_reasons) else "high"
        score_delta = min(35, 18 + (len(matched_reasons) * 6))

        indicators.append(Indicator(
            id="IND_CREDENTIAL_HARVESTING",
            title="Credential Harvesting Language",
            category="credentials",
            severity=severity,
            score_delta=score_delta,
            matched_terms=matched_snippets[:6],
            explanation=(
                f"Detected prompts asking to enter, verify, or reset sensitive credentials ({', '.join(matched_reasons[:2])}). "
                "Legitimate organizations rarely request credential re-verification through direct email links."
            )
        ))

    return indicators
