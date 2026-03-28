"""Okta — System Log Event Hook payload format.

Real Okta sends events via Event Hooks or pulled via System Log API.
Format: https://developer.okta.com/docs/reference/api/system-log/
"""
import random
from backend.engine.generators.base import BaseGenerator


class OktaGenerator(BaseGenerator):
    product_name = "Okta Identity"
    product_category = "itdr"

    EVENT_TYPES = [
        ("user.session.start", "User login to Okta"),
        ("user.session.end", "User logout from Okta"),
        ("user.authentication.auth_via_mfa", "MFA verification"),
        ("user.account.lock", "User account locked"),
        ("user.account.reset_password", "Password reset initiated"),
        ("security.attack.start", "Brute force attack detected"),
        ("security.threat.detected", "Suspicious activity detected"),
        ("policy.evaluate_sign_on", "Sign-on policy evaluation"),
        ("user.authentication.sso", "SSO authentication"),
        ("system.api_token.create", "API token created"),
        ("user.mfa.factor.deactivate", "MFA factor removed"),
        ("user.session.impersonation.initiate", "Admin impersonation started"),
    ]

    OUTCOMES_BY_SEVERITY = {
        "critical": [("FAILURE", "LOCKED_OUT"), ("FAILURE", "INVALID_CREDENTIALS")],
        "high":     [("FAILURE", "NETWORK_ZONE_BLACKLIST"), ("FAILURE", "MFA_ENROLL_REQUIRED")],
        "medium":   [("SUCCESS", None), ("FAILURE", "INVALID_CREDENTIALS")],
        "low":      [("SUCCESS", None), ("SUCCESS", None)],
    }

    SEVERITY_MAP = {
        "critical": "ERROR",
        "high": "WARN",
        "medium": "INFO",
        "low": "DEBUG",
    }

    CITIES = ["New York", "London", "Moscow", "Shanghai", "Sao Paulo", "Lagos", "Mumbai", "Berlin"]
    STATES = ["NY", "England", "Moscow", "Shanghai", "SP", "Lagos", "MH", "Berlin"]
    COUNTRIES = ["US", "GB", "RU", "CN", "BR", "NG", "IN", "DE"]

    BROWSERS = ["Chrome/122.0", "Firefox/124.0", "Edge/122.0", "Safari/17.3"]
    OS_LIST = ["Windows 11", "macOS Sonoma", "Ubuntu 22.04", "iOS 17.4", "Android 14"]

    def generate(self) -> dict:
        severity = self._pick_severity()
        event_type, display_msg = random.choice(self.EVENT_TYPES)
        user = self._pick_user()
        ip = self._pick_ip()
        geo_idx = random.randint(0, len(self.CITIES) - 1)
        outcome_result, outcome_reason = random.choice(self.OUTCOMES_BY_SEVERITY[severity])

        outcome = {"result": outcome_result}
        if outcome_reason:
            outcome["reason"] = outcome_reason

        return {
            "uuid": self._uuid(),
            "published": self._now_iso(),
            "eventType": event_type,
            "version": "0",
            "severity": self.SEVERITY_MAP[severity],
            "legacyEventType": event_type.replace(".", "_"),
            "displayMessage": display_msg,
            "actor": {
                "id": f"00u{self._uuid()[:12]}",
                "type": "User",
                "alternateId": f"{user}@corp.example.com",
                "displayName": user.replace(".", " ").title(),
            },
            "outcome": outcome,
            "client": {
                "userAgent": {
                    "rawUserAgent": f"Mozilla/5.0 ({random.choice(self.OS_LIST)}) {random.choice(self.BROWSERS)}",
                    "os": random.choice(self.OS_LIST),
                    "browser": random.choice(self.BROWSERS).split("/")[0],
                },
                "zone": random.choice(["DefaultZone", "OffNetwork", "BlockedIPs", "VPN"]),
                "device": random.choice(["Computer", "Mobile"]),
                "ipAddress": ip,
                "geographicalContext": {
                    "city": self.CITIES[geo_idx],
                    "state": self.STATES[geo_idx],
                    "country": self.COUNTRIES[geo_idx],
                    "postalCode": str(random.randint(10000, 99999)),
                    "geolocation": {
                        "lat": round(random.uniform(-60, 60), 4),
                        "lon": round(random.uniform(-180, 180), 4),
                    },
                },
            },
            "target": [
                {
                    "id": f"00u{self._uuid()[:12]}",
                    "type": "User",
                    "alternateId": f"{user}@corp.example.com",
                    "displayName": user.replace(".", " ").title(),
                }
            ],
            "authenticationContext": {
                "authenticationProvider": random.choice(["OKTA_AUTHENTICATION_PROVIDER", "ACTIVE_DIRECTORY", "FEDERATION"]),
                "credentialProvider": random.choice(["OKTA_CREDENTIAL_PROVIDER", "RSA", "DUO"]),
                "credentialType": random.choice(["PASSWORD", "OTP", "IWA"]),
                "externalSessionId": self._uuid()[:20],
            },
            "securityContext": {
                "asNumber": random.randint(1000, 65000),
                "asOrg": random.choice(["DigitalOcean", "Amazon", "Cloudflare", "OVH", "Hetzner"]),
                "isp": random.choice(["DigitalOcean", "AWS", "Cloudflare", "OVHcloud"]),
                "isProxy": random.choice([True, False]),
            },
        }
