import re
from typing import List
from ...models import Indicator

EXECUTIVE_PATTERNS = [
    (r'\b(?:are you at your desk|in a meeting(?: right now)?|busy in a conference|can\'?t talk on the phone)\b', "Executive availability pretext"),
    (r'\b(?:handle this (?:confidentially|discreetly|urgently)|keep this private)\b', "Enforced confidentiality / circumventing protocol"),
    (r'\b(?:sent from my (?:iphone|ipad|mobile device))\b', "Mobile signature pretext explaining briefness or lack of usual signature"),
]

IT_ADMIN_PATTERNS = [
    (r'\b(?:it (?:help[\s-]?desk|support|security|department|operations)|system administrator|network admin)\b', "IT administration impersonation"),
    (r'\b(?:microsoft (?:365|office|azure|team|security center)|office 365 admin)\b', "Microsoft / Office 365 brand impersonation"),
    (r'\b(?:google (?:workspace|cloud|security team)|apple security|paypal support)\b', "Major tech brand security authority impersonation"),
]

GENERIC_GREETINGS = [
    (r'^(?:dear (?:customer|client|user|member|account holder|sir/madam|valued customer)|attention:? account holder)', "Generic impersonation greeting"),
]


def check_impersonation(subject: str, body: str) -> List[Indicator]:
    combined = f"{subject}\n{body}".lower()
    first_lines = "\n".join(body.splitlines()[:5]).lower()
    indicators: List[Indicator] = []

    # Check Executive / BEC pretexting
    exec_matches = []
    for pattern, reason in EXECUTIVE_PATTERNS:
        matches = re.findall(pattern, combined, re.IGNORECASE)
        if matches:
            exec_matches.append((reason, matches))

    if exec_matches:
        snippets = [m[0] for _, matches in exec_matches for m in matches]
        indicators.append(Indicator(
            id="IND_EXECUTIVE_PRETEXT",
            title="Executive / Authority Pretexting (BEC)",
            category="impersonation",
            severity="critical" if len(exec_matches) >= 2 else "high",
            score_delta=25,
            matched_terms=snippets[:4],
            explanation=(
                "Language commonly seen in Business Email Compromise (BEC) attacks: "
                "The sender claims to be a busy executive who cannot speak by phone and requests discrete, rapid action to bypass corporate safeguards."
            )
        ))

    # Check IT / Tech Brand Impersonation
    it_matches = []
    for pattern, reason in IT_ADMIN_PATTERNS:
        matches = re.findall(pattern, combined, re.IGNORECASE)
        if matches:
            it_matches.append((reason, matches))

    if it_matches:
        snippets = [m[0] for _, matches in it_matches for m in matches]
        indicators.append(Indicator(
            id="IND_BRAND_AUTHORITY_IMPERSONATION",
            title="Brand / IT Authority Claims",
            category="impersonation",
            severity="high",
            score_delta=20,
            matched_terms=snippets[:4],
            explanation=(
                "Claims to represent official IT administrators, Microsoft 365, or security operations. "
                "Phishing campaigns frequently weaponize trusted corporate identities to trick staff into complying."
            )
        ))

    # Check impersonal generic greeting
    for pattern, reason in GENERIC_GREETINGS:
        if re.search(pattern, first_lines, re.IGNORECASE):
            indicators.append(Indicator(
                id="IND_GENERIC_GREETING",
                title="Generic / Depersonalized Greeting",
                category="impersonation",
                severity="low",
                score_delta=8,
                matched_terms=["Generic greeting found at start of email"],
                explanation=(
                    "The email uses a generic salutation (e.g., 'Dear Customer', 'Attention Account Holder') rather than addressing the recipient by name. "
                    "This is typical of automated mass phishing blasts."
                )
            ))
            break

    return indicators
