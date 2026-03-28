"""Microsoft Entra ID (Azure AD) — Sign-in and audit log event format.

Real Entra ID exposes sign-in logs via Graph API or streams to SIEM.
Format: https://learn.microsoft.com/en-us/graph/api/resources/signin
"""
import random
from backend.generators.base import BaseGenerator


class EntraIDGenerator(BaseGenerator):
    product_name = "Microsoft Entra ID"
    product_category = "itdr"

    OPERATION_NAMES = [
        "Sign-in activity",
        "Risky sign-in detected",
        "User risk policy triggered",
        "MFA registration activity",
        "Password reset by admin",
        "Conditional Access policy applied",
        "App consent granted",
        "Privileged role assignment",
        "Service principal sign-in",
        "Token issuance started",
    ]

    RISK_LEVELS = {
        "critical": "high",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }

    RISK_STATES = ["atRisk", "confirmedCompromised", "remediated", "dismissed", "none"]

    RISK_DETAIL = [
        "none", "userPerformedSecuredPasswordChange", "userPerformedSecuredPasswordReset",
        "adminConfirmedSigninSafe", "aiConfirmedSigninSafe", "adminDismissedAllRiskForUser",
        "unfamiliarFeatures", "maliciousIPAddress", "anomalousToken", "tokenIssuerAnomaly",
    ]

    RESULT_TYPES = {
        "critical": [("50126", "Invalid username or password"), ("53003", "Blocked by Conditional Access")],
        "high": [("50076", "MFA required"), ("50074", "Strong authentication required")],
        "medium": [("0", "Success"), ("50140", "Keep me signed in interrupt")],
        "low": [("0", "Success"), ("0", "Success")],
    }

    CA_STATUSES = ["success", "failure", "notApplied"]
    CA_POLICIES = [
        "Require MFA for all users", "Block legacy authentication",
        "Require compliant device", "Block risky sign-ins",
        "Require MFA for admins", "Session sign-in frequency",
    ]

    APP_NAMES = [
        "Microsoft Office 365", "Microsoft Teams", "Azure Portal",
        "Microsoft Exchange Online", "SharePoint Online", "Power BI",
        "Microsoft Graph Explorer", "Custom LOB App",
    ]

    CLIENT_APPS = ["browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"]
    AUTH_METHODS = ["password", "passwordless", "fido2", "microsoftAuthenticator", "sms"]

    CITIES = ["New York", "London", "Amsterdam", "Tokyo", "Sydney", "Toronto", "Berlin", "Mumbai"]
    STATES = ["New York", "England", "North Holland", "Tokyo", "NSW", "Ontario", "Berlin", "Maharashtra"]
    COUNTRIES = ["US", "GB", "NL", "JP", "AU", "CA", "DE", "IN"]

    def generate(self) -> dict:
        severity = self._pick_severity()
        user = self._pick_user()
        ip = self._pick_ip()
        geo_idx = random.randint(0, len(self.CITIES) - 1)
        result_code, result_desc = random.choice(self.RESULT_TYPES[severity])
        risk_level = self.RISK_LEVELS[severity]
        app = random.choice(self.APP_NAMES)

        ca_results = []
        for _ in range(random.randint(1, 3)):
            ca_results.append({
                "id": self._uuid(),
                "displayName": random.choice(self.CA_POLICIES),
                "result": random.choice(self.CA_STATUSES),
                "enforcedGrantControls": random.choice([["mfa"], ["compliantDevice"], []]),
                "enforcedSessionControls": [],
            })

        return {
            "id": self._uuid(),
            "createdDateTime": self._now_iso(),
            "operationName": random.choice(self.OPERATION_NAMES),
            "userDisplayName": user.replace(".", " ").title(),
            "userPrincipalName": f"{user}@corp.example.com",
            "userId": self._uuid(),
            "appId": self._uuid(),
            "appDisplayName": app,
            "ipAddress": ip,
            "clientAppUsed": random.choice(self.CLIENT_APPS),
            "authenticationMethodsUsed": [random.choice(self.AUTH_METHODS)],
            "resourceDisplayName": app,
            "status": {
                "errorCode": int(result_code),
                "failureReason": result_desc if result_code != "0" else None,
                "additionalDetails": None,
            },
            "resultType": result_code,
            "resultDescription": result_desc,
            "conditionalAccessStatus": random.choice(self.CA_STATUSES),
            "appliedConditionalAccessPolicies": ca_results,
            "isInteractive": random.choice([True, True, False]),
            "riskLevelAggregated": risk_level if severity in ("critical", "high") else "none",
            "riskLevelDuringSignIn": risk_level if severity in ("critical", "high") else "none",
            "riskState": random.choice(self.RISK_STATES) if severity in ("critical", "high") else "none",
            "riskDetail": random.choice(self.RISK_DETAIL),
            "location": {
                "city": self.CITIES[geo_idx],
                "state": self.STATES[geo_idx],
                "countryOrRegion": self.COUNTRIES[geo_idx],
                "geoCoordinates": {
                    "latitude": round(random.uniform(-60, 60), 4),
                    "longitude": round(random.uniform(-180, 180), 4),
                },
            },
            "deviceDetail": {
                "operatingSystem": random.choice(["Windows 11", "macOS 14", "iOS 17", "Android 14"]),
                "browser": random.choice(["Edge 122", "Chrome 122", "Safari 17", "Firefox 124"]),
                "isCompliant": random.choice([True, False]),
                "isManaged": random.choice([True, False]),
                "trustType": random.choice(["AzureAd", "Hybrid", "ServerAd", ""]),
            },
        }
