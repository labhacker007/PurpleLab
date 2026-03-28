"""Proofpoint TAP — SIEM API / webhook delivered messages & clicks format.

Real Proofpoint TAP sends events via SIEM API polling or webhook.
Format: https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/SIEM_API
"""
import random
from backend.engine.generators.base import BaseGenerator


class ProofpointGenerator(BaseGenerator):
    product_name = "Proofpoint TAP"
    product_category = "email"

    SUBJECTS = [
        "Urgent: Invoice #{num} Payment Required",
        "Action Required: Verify Your Account",
        "RE: Q4 Budget Review - Updated Figures",
        "Shared Document: Company Policy Update.pdf",
        "IT Security: Password Expiry Notice",
        "DocuSign: Please review and sign",
        "Voicemail from +1-555-{num}",
        "FW: Wire Transfer Request - Confidential",
        "Your package delivery failed - Retry",
        "Meeting Notes - Board Review {num}",
    ]

    SENDER_DOMAINS = [
        "mail-service.example.net", "secure-docs.example.org", "hr-portal.example.com",
        "notify.example.net", "accounts-verify.example.org", "docusign-fake.example.com",
    ]

    RECIPIENT_DOMAINS = ["corp.example.com", "company.example.com"]

    CLASSIFICATIONS = ["phish", "malware", "spam", "impostor"]
    THREAT_TYPES = ["url", "attachment", "messageText"]

    ATTACHMENT_NAMES = [
        "Invoice_2026.pdf", "Policy_Update.docx", "Payment_Details.xlsx",
        "Scanned_Document.pdf.exe", "Report_Q4.zip", "resume_2026.doc",
    ]

    def _make_threat_info(self, severity: str) -> dict:
        threat_type = random.choice(self.THREAT_TYPES)
        classification = random.choice(self.CLASSIFICATIONS)
        threat_url = random.choice([
            f"https://{random.choice(self.SENDER_DOMAINS)}/click?id={self._uuid()[:8]}",
            f"https://{self._pick_domain()}/payload",
        ])

        info = {
            "threat": self._pick_hash() if threat_type == "attachment" else threat_url,
            "threatID": self._uuid(),
            "threatType": threat_type,
            "threatStatus": "active",
            "threatTime": self._now_iso(),
            "classification": classification,
            "threatUrl": threat_url,
        }
        if threat_type == "attachment":
            info["fileName"] = random.choice(self.ATTACHMENT_NAMES)
            info["sha256"] = "".join(random.choices("0123456789abcdef", k=64))
        return info

    def generate(self) -> dict:
        severity = self._pick_severity()
        user = self._pick_user()
        sender_user = random.choice(["noreply", "admin", "support", "billing", "hr"])
        sender = f"{sender_user}@{random.choice(self.SENDER_DOMAINS)}"
        recipient = f"{user}@{random.choice(self.RECIPIENT_DOMAINS)}"
        subject = random.choice(self.SUBJECTS).format(num=random.randint(1000, 99999))
        is_click = random.random() < 0.3

        threat_info = self._make_threat_info(severity)
        spam_score = {"critical": 95, "high": 80, "medium": 55, "low": 25}[severity]
        spam_score += random.randint(-10, 10)

        payload = {
            "GUID": self._uuid(),
            "QID": f"{''.join(random.choices('0123456789abcdefghijklmnop', k=12))}",
            "sender": sender,
            "recipient": [recipient],
            "subject": subject,
            "messageTime": self._now_iso(),
            "messageSize": random.randint(1500, 250000),
            "spamScore": max(0, min(100, spam_score)),
            "phishScore": random.randint(0, 100) if threat_info["classification"] == "phish" else 0,
            "impostorScore": round(random.uniform(0, 1), 2),
            "malwareScore": random.randint(0, 100) if threat_info["classification"] == "malware" else 0,
            "completelyRewritten": random.choice([True, False]),
            "threatsInfoMap": [threat_info],
            "senderIP": self._pick_ip(),
            "headerFrom": sender,
            "headerReplyTo": sender,
            "fromAddress": [sender],
            "toAddress": [recipient],
            "messageParts": [
                {
                    "disposition": "inline",
                    "contentType": "text/html",
                    "sha256": "".join(random.choices("0123456789abcdef", k=64)),
                }
            ],
        }

        if is_click:
            payload["clickTime"] = self._now_iso()
            payload["clickIP"] = self._pick_ip()
            payload["url"] = threat_info.get("threatUrl", "")
            payload["userAgent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0"

        return payload
