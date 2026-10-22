from typing import List, Dict

SAMPLE_EMAILS: List[Dict[str, str]] = [
    {
        "id": "phishing_m365",
        "label": "Microsoft 365 Account Suspension (Phishing)",
        "type": "phishing",
        "sender": "Microsoft 365 Security Alert <no-reply@security-center-update92.xyz>",
        "subject": "CRITICAL ALERT: Your Microsoft 365 Account Will Be Suspended Within 24 Hours",
        "body": (
            "Dear Valued Customer,\n\n"
            "We detected unauthorized login attempts from an unknown device in Moscow, Russia on your Microsoft 365 organization account.\n\n"
            "To prevent unauthorized access, your account will be suspended within 24 hours unless you verify your identity.\n\n"
            "Please click here to login and confirm your credentials to avoid account closure:\n"
            "http://microsoft-verify-account.security-center-update92.xyz/login.php?ref=365\n\n"
            "Failure to comply will result in immediate termination of your email inbox and OneDrive files.\n\n"
            "Microsoft Security Operations Desk\n"
            "One Microsoft Way, Redmond, WA"
        )
    },
    {
        "id": "phishing_bec",
        "label": "CEO Urgent Wire / Gift Cards (Executive BEC)",
        "type": "phishing",
        "sender": "Robert Vance - CEO <robert.vance.exec@gmail.com>",
        "subject": "Urgent Request - Wire Transfer / Gift Cards (In Meeting)",
        "body": (
            "Are you at your desk right now?\n\n"
            "I am currently in an executive board meeting and cannot talk on the phone. "
            "I need you to handle this urgently and confidentially.\n\n"
            "Please process an immediate wire transfer of $18,450 to our new supplier before 3:00 PM today. "
            "If the wire system is undergoing maintenance, purchase 5 Apple gift cards of $500 each and send me the codes on the back.\n\n"
            "Do not discuss this with anyone until the transaction is completed. I will sign off when I get out of the meeting.\n\n"
            "Sent from my iPhone"
        )
    },
    {
        "id": "suspicious_invoice",
        "label": "Overdue Invoice with Shortener (Suspicious)",
        "type": "suspicious",
        "sender": "Accounts Receivable <billing@quickinvoicing-sys.top>",
        "subject": "OVERDUE INVOICE #INV-9042 - Immediate Payment Required",
        "body": (
            "Dear Sir/Madam,\n\n"
            "Our records indicate invoice #INV-9042 for $3,850.00 is past due. "
            "Immediate payment is required to avoid late penalties and legal escalation.\n\n"
            "You can review and download the itemized statement here:\n"
            "https://bit.ly/inv-statement-download\n\n"
            "Please verify your payment details immediately.\n\n"
            "Billing Department"
        )
    },
    {
        "id": "benign_team_sync",
        "label": "Internal Team Sync & Agenda (Benign)",
        "type": "benign",
        "sender": "Sarah Jenkins <sjenkins@acmecorp.com>",
        "subject": "Team Weekly Sync - Agenda & Q3 Project Updates",
        "body": (
            "Hi team,\n\n"
            "Hope everyone is having a productive week! Ahead of our Friday sync at 10:00 AM, "
            "please review the Q3 roadmap updates on our internal Notion workspace:\n"
            "https://internal.acmecorp.com/wiki/q3-roadmap\n\n"
            "Key talking points:\n"
            "1. Sprint 14 retrospectives\n"
            "2. Design system migration progress\n"
            "3. Open headcount updates\n\n"
            "Let me know if you have items to add to the agenda by Thursday afternoon.\n\n"
            "Best regards,\n"
            "Sarah Jenkins\n"
            "Product Lead, Acme Corp"
        )
    },
    {
        "id": "benign_newsletter",
        "label": "Security Community Newsletter (Benign)",
        "type": "benign",
        "sender": "Cybersecurity Weekly Digest <newsletter@cybersec-weekly.org>",
        "subject": "This Week in InfoSec: Zero-Day Roundups and Best Practices",
        "body": (
            "Hello Security Enthusiasts,\n\n"
            "Welcome to this week's edition of the Cybersecurity Weekly Digest. In today's issue:\n"
            "- Overview of the latest CVE advisories\n"
            "- Industry trends in zero-trust architecture\n"
            "- Upcoming cybersecurity webinars and conferences\n\n"
            "Read the full issue on our publication website: https://cybersec-weekly.org/editions/issue-182\n\n"
            "You are receiving this email because you subscribed to our community updates. "
            "To manage preferences, visit https://cybersec-weekly.org/preferences\n\n"
            "Stay safe,\n"
            "The CyberSec Weekly Team"
        )
    }
]
