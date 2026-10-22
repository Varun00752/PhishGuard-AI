import re
import urllib.parse
from typing import List, Tuple
from ..models import ExtractedURL

# Regex to find URLs or bare web links in untrusted text safely without executing them
URL_PATTERN = re.compile(
    r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,12}/)(?:[^\s()<>{}\[\]"\']|\([^\s()<>{}\[\]"\']*\))+)',
    re.IGNORECASE
)

# Known URL shortener services commonly used to obscure phishing landing pages
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "rebrand.ly", "cutt.ly", "shorturl.at",
    "tiny.cc", "v.gd", "soo.gd", "rb.gy", "s.id"
}

# High-risk TLDs frequently abused in automated bulk phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "rest", "tk", "ml", "ga", "cf", "gq",
    "work", "click", "link", "loan", "cam", "fit", "icu", "surf", "monster"
}

# High-value brand names targeted in deceptive domain registrations
TARGET_BRANDS = [
    "microsoft", "office365", "office", "outlook", "google", "gmail",
    "apple", "icloud", "amazon", "paypal", "netflix", "chase", "wellsfargo",
    "bankofamerica", "citibank", "docusign", "dropbox", "facebook",
    "meta", "instagram", "linkedin", "irs", "gov", "coinbase", "binance"
]

# Sensitive path keywords in untrusted landing pages
SENSITIVE_PATH_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "secure",
    "password", "reset", "credential", "auth", "account", "banking",
    "confirm", "wallet", "invoice", "payment"
]

IP_V4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)


def extract_and_analyze_urls(text: str) -> List[ExtractedURL]:
    """
    Safely extracts and statically inspects URLs in text.
    NEVER establishes network connections or opens links.
    """
    if not text:
        return []

    raw_matches = URL_PATTERN.findall(text)
    seen = set()
    results: List[ExtractedURL] = []

    for match in raw_matches:
        # Strip trailing punctuation often caught by regex in sentences
        cleaned = match.rstrip(".,;:!?'\")>]}")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)

        # Normalize URL scheme for parsing
        parse_target = cleaned
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', cleaned):
            parse_target = "http://" + cleaned

        try:
            parsed = urllib.parse.urlparse(parse_target)
        except Exception:
            # If parsing fails, flag as malformed suspicious link
            results.append(ExtractedURL(
                url=cleaned,
                domain="malformed",
                is_suspicious=True,
                flags=["Malformed URL Structure"],
                risk_level="suspicious"
            ))
            continue

        domain = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        scheme = parsed.scheme.lower()
        flags: List[str] = []

        # 1. Check scheme
        if scheme not in ("http", "https"):
            flags.append(f"Unsafe Scheme: {scheme}:")

        # 2. Check for IP address host
        if IP_V4_PATTERN.match(domain):
            flags.append("Raw IPv4 Address Host (Bypasses Domain Reputation)")
        elif domain.startswith("[") and domain.endswith("]"):
            flags.append("Raw IPv6 Address Host")

        # 3. Check for URL shorteners
        if domain in KNOWN_SHORTENERS:
            flags.append(f"URL Shortener ({domain}) Hides Real Destination")

        # 4. Check for UserInfo trick (e.g. https://google.com@evil.com)
        if parsed.username or parsed.password or "@" in cleaned.split("?")[0]:
            flags.append("Deceptive '@' Credential/Redirect In URL")

        # 5. Check for non-standard ports
        if parsed.port and parsed.port not in (80, 443):
            flags.append(f"Non-Standard Port :{parsed.port}")

        # 6. Check for Punycode / Homoglyph representation
        if "xn--" in domain:
            flags.append("Internationalized/Punycode Domain (Potential Homoglyph Spoof)")

        # 7. Check for suspicious TLDs
        tld = domain.split(".")[-1] if "." in domain else ""
        if tld in SUSPICIOUS_TLDS:
            flags.append(f"High-Risk TLD (.{tld}) Frequently Used in Phishing")

        # 8. Check for excessive subdomains (e.g. login.secure.verify.evil.com)
        parts = domain.split(".")
        if len(parts) > 4 and not IP_V4_PATTERN.match(domain):
            flags.append("Excessive Subdomains (Obfuscation Tactic)")

        # 9. Brand lookalikes / typosquatting in domain
        matched_brand = None
        for brand in TARGET_BRANDS:
            if brand in domain:
                # If brand is in domain, but domain is NOT the official exact brand domain
                # e.g., 'microsoft-security.com' vs 'microsoft.com'
                if not (domain == f"{brand}.com" or domain.endswith(f".{brand}.com")):
                    matched_brand = brand
                    break

        if matched_brand:
            flags.append(f"Deceptive Brand Lookalike (Mentions '{matched_brand}' on Unofficial Domain)")

        # 10. Sensitive authentication keyword in path of non-standard domain
        if any(keyword in path for keyword in SENSITIVE_PATH_KEYWORDS):
            if matched_brand or tld in SUSPICIOUS_TLDS or IP_V4_PATTERN.match(domain) or len(parts) > 3:
                flags.append("Credential/Verification Path on Suspicious Host")

        # Determine risk level
        is_suspicious = len(flags) > 0
        if any("Brand Lookalike" in f or "Raw IP" in f or "Deceptive '@'" in f for f in flags):
            risk_level = "high"
        elif is_suspicious:
            risk_level = "suspicious"
        else:
            risk_level = "safe"

        results.append(ExtractedURL(
            url=cleaned,
            domain=domain or "unknown",
            is_suspicious=is_suspicious,
            flags=flags,
            risk_level=risk_level
        ))

    return results
