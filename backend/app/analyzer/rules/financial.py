import re
from typing import List
from ...models import Indicator

FINANCIAL_PATTERNS = [
    (r'\b(?:wire transfer|ach transfer|bank transfer|swift code|routing number)\b', "Wire transfer or banking routing instructions"),
    (r'\b(?:gift cards?|itunes|apple gift|steam card|google play card|vanilla visa)\b', "Request for gift cards or untraceable payment cards"),
    (r'\b(?:bitcoin|btc|cryptocurrency|crypto wallet|ethereum|eth|tether|usdt)\b', "Cryptocurrency payment demands"),
    (r'\b(?:overdue (?:invoice|payment|bill)|unpaid balance|past due|outstanding invoice)\b', "Unsolicited overdue invoice claim"),
    (r'\b(?:direct deposit|payroll details|update bank account|salary routing)\b', "Request to alter payroll or bank account details"),
    (r'\b(?:claim your (?:refund|prize|settlement|inheritance|payout)|lottery winner)\b', "Unexpected monetary payout or refund lure"),
]


def check_financial(subject: str, body: str) -> List[Indicator]:
    combined = f"{subject}\n{body}".lower()
    indicators: List[Indicator] = []

    matched_reasons = []
    matched_snippets = []

    for pattern, reason in FINANCIAL_PATTERNS:
        matches = re.findall(pattern, combined, re.IGNORECASE)
        if matches:
            matched_reasons.append(reason)
            for m in matches:
                clean_m = m.strip()
                if clean_m and clean_m not in matched_snippets:
                    matched_snippets.append(clean_m)

    if matched_reasons:
        is_crypto_or_giftcard = any("gift card" in r.lower() or "cryptocurrency" in r.lower() for r in matched_reasons)
        severity = "critical" if is_crypto_or_giftcard else "high"
        score_delta = min(35, 20 + (len(matched_reasons) * 7))

        indicators.append(Indicator(
            id="IND_FINANCIAL_PRESSURE",
            title="Financial Scam & Payment Demands",
            category="financial",
            severity=severity,
            score_delta=score_delta,
            matched_terms=matched_snippets[:6],
            explanation=(
                f"Identified high-risk financial payment cues ({', '.join(matched_reasons[:2])}). "
                "Requests involving gift cards, untraceable transfers, or sudden payroll/invoice changes are classic signatures of Business Email Compromise (BEC)."
            )
        ))

    return indicators
