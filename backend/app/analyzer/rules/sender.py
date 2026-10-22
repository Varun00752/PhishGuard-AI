import re
import email.utils
from typing import List
from ...models import Indicator

FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "zoho.com", "mail.com", "gmx.com", "yandex.com", "icloud.com"
}

SUSPICIOUS_SENDER_TLDS = {
    "xyz", "top", "buzz", "rest", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "link", "loan", "cam", "fit", "icu", "surf"
}

BRAND_KEYWORDS = [
    "microsoft", "office365", "google", "apple", "paypal", "amazon",
    "netflix", "chase", "wellsfargo", "bank of america", "citi", "docusign",
    "dropbox", "helpdesk", "it support", "security team", "admin"
]


def check_sender_inconsistencies(sender_header: str, subject: str = "", body: str = "") -> List[Indicator]:
    if not sender_header:
        return [Indicator(
            id="IND_EMPTY_SENDER",
            title="Missing / Unspecified Sender Information",
            category="sender",
            severity="medium",
            score_delta=10,
            matched_terms=["Empty sender field"],
            explanation="The email sender could not be verified because no sender address or header was provided."
        )]

    display_name, email_address = email.utils.parseaddr(sender_header)
    display_name_lower = display_name.lower()
    email_address_lower = email_address.lower()

    indicators: List[Indicator] = []

    # If parseaddr didn't separate them (e.g. user just wrote support@domain.com)
    if not email_address_lower and "@" in sender_header:
        email_address_lower = sender_header.strip().lower()

    domain = email_address_lower.split("@")[-1] if "@" in email_address_lower else ""
    tld = domain.split(".")[-1] if "." in domain else ""

    # 1. Display name spoofing (e.g., Display name: "Microsoft Security", Sender: "evil@random.xyz")
    for brand in BRAND_KEYWORDS:
        if brand in display_name_lower:
            # Check if domain matches brand
            brand_token = brand.replace(" ", "")
            if brand_token not in domain:
                indicators.append(Indicator(
                    id="IND_DISPLAY_NAME_SPOOF",
                    title="Display Name Spoofing Detected",
                    category="sender",
                    severity="critical",
                    score_delta=30,
                    matched_terms=[f"Display: '{display_name}'", f"Actual Address: '{email_address}'"],
                    explanation=(
                        f"The sender displays a recognizable brand or role ('{display_name}'), but the underlying email address domain "
                        f"is '{domain}'. Attackers use display name deception because many mobile email clients hide the actual address."
                    )
                ))
                break

    # 2. Executive / IT Support using free webmail (e.g., "CEO John" <ceo789@gmail.com>)
    is_freemail = domain in FREE_MAIL_PROVIDERS
    is_claimed_corporate = any(
        kw in display_name_lower or kw in subject.lower()
        for kw in ["ceo", "cfo", "director", "president", "it support", "help desk", "administrator", "billing department"]
    )
    if is_freemail and is_claimed_corporate:
        indicators.append(Indicator(
            id="IND_FREEMAIL_IMPERSONATION",
            title="Corporate / Executive Identity on Free Webmail",
            category="sender",
            severity="high",
            score_delta=25,
            matched_terms=[f"Domain: {domain}", f"Display/Subject claim: {display_name or subject}"],
            explanation=(
                f"The sender is using a free public webmail service ({domain}) while claiming to be corporate leadership, IT, or administrative staff. "
                "Official organizations send administrative and executive messages from owned corporate domain addresses."
            )
        ))

    # 3. Suspicious TLD in sender domain
    if tld in SUSPICIOUS_SENDER_TLDS:
        indicators.append(Indicator(
            id="IND_SUSPICIOUS_SENDER_TLD",
            title="Sender Domain on High-Risk TLD",
            category="sender",
            severity="medium",
            score_delta=15,
            matched_terms=[f".{tld} domain: {domain}"],
            explanation=(
                f"The sender domain '{domain}' uses top-level domain '.{tld}', which is frequently associated with disposable domains "
                "used in automated spam and phishing waves."
            )
        ))

    # 4. Excessive hyphens or digits in sender domain (e.g., service-security-update24-login.com)
    if domain.count("-") >= 2 or sum(c.isdigit() for c in domain) >= 4:
        indicators.append(Indicator(
            id="IND_SUSPICIOUS_SENDER_DOMAIN_SYNTAX",
            title="Suspicious Domain Structure (Hyphens/Digits)",
            category="sender",
            severity="medium",
            score_delta=12,
            matched_terms=[domain],
            explanation=(
                f"The domain '{domain}' contains multiple hyphens or clustered digits, a pattern common in automated typosquatting "
                "and phishing infrastructure created to mimic legitimate domains."
            )
        ))

    return indicators
