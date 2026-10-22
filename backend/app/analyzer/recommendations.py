from typing import List
from ..models import Indicator, ExtractedURL


def generate_recommendations(
    score: int,
    indicators: List[Indicator],
    extracted_urls: List[ExtractedURL]
) -> List[str]:
    recs: List[str] = []

    has_suspicious_urls = any(u.is_suspicious for u in extracted_urls)
    has_urls = len(extracted_urls) > 0
    categories = {ind.category for ind in indicators}

    if score >= 70:
        recs.append("CRITICAL: Do NOT click any links, download attachments, or reply to this sender.")
        recs.append("Forward this email immediately to your organization's Security Operations Center (SOC) or IT Security team.")
        recs.append("Flag and delete or quarantine the message in your email client.")
    elif score >= 30:
        recs.append("Treat this message with caution. Multiple suspicious indicators were flagged.")
        recs.append("Verify the sender's identity using a separate, trusted channel before taking any action.")

    if has_urls:
        if has_suspicious_urls:
            recs.append("Deceptive or disguised web links detected. Do NOT navigate to the addresses found in this message.")
        recs.append("If you need to access an account, navigate to the official website manually via your browser bookmarks rather than clicking links in emails.")

    if "credentials" in categories:
        recs.append("Never share passwords, MFA one-time codes, or PINs. Legitimate providers will never ask for your password via email.")
        recs.append("If you previously entered credentials on a link from this email, immediately change your password on the official website and enable multi-factor authentication (MFA).")

    if "financial" in categories:
        recs.append("Halt any wire transfer, gift card purchase, or bank routing alteration until verbally confirmed with the requesting party via a known, pre-established phone number.")

    if "impersonation" in categories or "sender" in categories:
        recs.append("The sender appears to be spoofing or misrepresenting their true identity. Do NOT rely on the display name or reply headers in this email.")

    if score < 30:
        recs.append("Always inspect unfamiliar attachments or unexpected links even in low-risk communications.")
        recs.append("When in doubt, contact the alleged sender through an internal corporate directory.")

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    return deduped[:6]
