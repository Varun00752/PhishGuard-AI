import email
import re
import urllib.parse
from email import policy
from typing import Dict


def unwrap_tracking_url(url: str) -> str:
    """
    Unwraps the real target destination from known email click-tracking redirects
    such as AWS SES (*.awstrack.me).
    """
    if not url:
        return ""

    # AWS SES tracking URLs: https://<id>.r.<region>.awstrack.me/L0/<encoded_url>/1/<id>/<hash>
    if "awstrack.me" in url:
        m = re.search(r'/(?:[A-Za-z0-9]+)/((?:https?|http):%2F%2F[^ \t\r\n\x22\x27)]+)', url, re.IGNORECASE)
        if m:
            unquoted = urllib.parse.unquote(m.group(1))
            # Remove trailing SES tracking path tokens: /1/<hash>/<sig>
            cleaned = re.sub(r'/[0-9]/[0-9a-fA-F\-]{8,}/.*$', '', unquoted)
            return cleaned

    return url


def clean_html_to_text(html_content: str) -> str:
    """
    Converts rich HTML email content into clean, readable plaintext.
    Preserves meaningful hyperlinks and unwraps click-tracking redirects.
    Eliminates excessive empty table/div formatting whitespace.
    """
    # 1. Remove style, script, and head blocks
    text = re.sub(r'<(?:style|script|head)[^>]*>.*?</(?:style|script|head)>', '', html_content, flags=re.DOTALL | re.IGNORECASE)

    # 2. Extract and format hyperlinks
    def link_repl(match):
        raw_href = match.group(1).strip()
        href = unwrap_tracking_url(raw_href)
        raw_inner = match.group(2)
        # Strip internal tags inside anchor
        inner_text = re.sub(r'<[^>]+>', ' ', raw_inner).strip()
        inner_text = re.sub(r'\s+', ' ', inner_text)

        if not inner_text or inner_text.lower() == href.lower():
            return href
        return f"{inner_text} ({href})"

    text = re.sub(r'<a\s+(?:[^>]*?\s+)?href=[\'"]([^\'"]*)[\'"][^>]*>(.*?)</a>', link_repl, text, flags=re.DOTALL | re.IGNORECASE)

    # 3. Convert block level elements to line breaks
    text = re.sub(r'<(?:br|p|div|tr|li|h[1-6]|table|td|th)[^>]*>', '\n', text, flags=re.IGNORECASE)

    # 4. Strip any remaining HTML tags
    text = re.sub(r'<[^>]+>', ' ', text)

    # 5. Decode common HTML entities
    text = text.replace('&nbsp;', ' ')
    text = text.replace('&amp;', '&')
    text = text.replace('&lt;', '<')
    text = text.replace('&gt;', '>')
    text = text.replace('&quot;', '"')
    text = text.replace('&#39;', "'")
    text = text.replace('&copy;', '©')

    # 6. Normalize whitespace: trim lines and remove consecutive empty blank lines
    lines = [line.strip() for line in text.split('\n')]
    clean_lines = []
    for line in lines:
        if line:
            clean_lines.append(line)
        elif clean_lines and clean_lines[-1] != '':
            clean_lines.append('')

    return '\n'.join(clean_lines).strip()


def parse_email_bytes(content: bytes) -> Dict[str, str]:
    """
    Parses raw email bytes (.eml or RFC 822 format) and extracts sender, subject, and body.
    Handles MIME multipart, quoted-printable, base64, and HTML content cleanly.
    """
    try:
        msg = email.message_from_bytes(content, policy=policy.default)
        sender = str(msg.get("From", "") or "").strip()
        subject = str(msg.get("Subject", "") or "").strip()

        body = ""
        # Prefer plain text, fallback to HTML
        body_part = msg.get_body(preferencelist=("plain", "html"))
        if body_part:
            content_type = body_part.get_content_type()
            raw_body = body_part.get_content()
            if content_type == "text/html":
                body = clean_html_to_text(str(raw_body))
            else:
                body = str(raw_body).strip()
        else:
            # Fallback if no body part identified
            raw_str = content.decode("utf-8", errors="replace").strip()
            if "<html" in raw_str.lower() or "<div" in raw_str.lower():
                body = clean_html_to_text(raw_str)
            else:
                body = raw_str

        # If headers couldn't be parsed, treat entire content as body
        if not sender and not subject and not body:
            body = content.decode("utf-8", errors="replace").strip()

        return {
            "sender": sender,
            "subject": subject,
            "body": body,
        }
    except Exception:
        # Ultimate fallback for arbitrary text files
        text = content.decode("utf-8", errors="replace").strip()
        return {
            "sender": "",
            "subject": "",
            "body": text,
        }
