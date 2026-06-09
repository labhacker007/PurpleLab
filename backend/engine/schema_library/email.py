"""Email security vendor-specific benign event templates.

Sourced from official vendor documentation:
- Microsoft 365: Office 365 Management Activity API (Operation, UserId, ClientIP)
- Proofpoint TAP: SIEM API (fromAddress, toAddresses, classification, eventTypeString)
- Google Workspace: Admin Reports Activity API (actor.email, events[].name)
- Mimecast: SIEM integration log format
"""
from __future__ import annotations

from typing import Any

VENDOR_BENIGN_TEMPLATES: dict[str, list[dict[str, Any]]] = {

    # ── Microsoft 365 / Exchange Online ─────────────────────────────────────
    "m365": [
        {
            "severity": "info",
            "title_template": "M365: MailItemsAccessed — {username} read {smtp_from}",
            "payload_template": {
                "CreationTime": "{timestamp}",
                "RecordType": "50",
                "Operation": "MailItemsAccessed",
                "UserType": "0",
                "UserId": "{email}",
                "UserKey": "{email}",
                "Workload": "Exchange",
                "ClientIP": "{src_ip}",
                "ResultStatus": "Succeeded",
                "OrganizationId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "Scope": "Online",
                "MailboxGuid": "12345678-abcd-1234-abcd-123456789012",
                "ClientInfoString": "Client=OWA;Action=ViaProxy",
                "FolderPath": "\\Inbox",
            },
        },
        {
            "severity": "info",
            "title_template": "M365: Send — {username} sent email to {smtp_to}",
            "payload_template": {
                "CreationTime": "{timestamp}",
                "RecordType": "2",
                "Operation": "Send",
                "UserType": "0",
                "UserId": "{email}",
                "Workload": "Exchange",
                "ClientIP": "{src_ip}",
                "ResultStatus": "Succeeded",
                "OrganizationId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "SenderMailboxGuid": "12345678-abcd-1234-abcd-123456789012",
                "RecipientAddress": "{smtp_to}",
                "Subject": "Weekly status update",
            },
        },
        {
            "severity": "info",
            "title_template": "M365: UserLoggedIn — {username} signed in to Exchange",
            "payload_template": {
                "CreationTime": "{timestamp}",
                "RecordType": "15",
                "Operation": "UserLoggedIn",
                "UserType": "0",
                "UserId": "{email}",
                "Workload": "AzureActiveDirectory",
                "ClientIP": "{src_ip}",
                "ResultStatus": "Succeeded",
                "OrganizationId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "DeviceProperties": [{"Name": "OS", "Value": "Windows 10"}],
            },
        },
        {
            "severity": "info",
            "title_template": "M365: FileAccessed — {username} opened OneDrive document",
            "payload_template": {
                "CreationTime": "{timestamp}",
                "RecordType": "6",
                "Operation": "FileAccessed",
                "UserType": "0",
                "UserId": "{email}",
                "Workload": "SharePoint",
                "ClientIP": "{src_ip}",
                "ResultStatus": "Succeeded",
                "ObjectId": "https://contoso-my.sharepoint.com/personal/{username}/Documents/Q4_Report.xlsx",
                "SourceFileName": "Q4_Report.xlsx",
                "SiteUrl": "https://contoso-my.sharepoint.com/personal/{username}",
                "UserAgent": "Mozilla/5.0",
            },
        },
    ],

    # ── Proofpoint TAP ──────────────────────────────────────────────────────
    "proofpoint": [
        {
            "severity": "info",
            "title_template": "Proofpoint TAP: Delivered — {smtp_from} → {smtp_to}",
            "payload_template": {
                "messageTime": "{timestamp}",
                "messageID": "AANCf-Arr4KLvB7kTL3Qo8A5@mail.{domain}",
                "GUID": "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII",
                "fromAddress": ["{smtp_from}"],
                "toAddresses": ["{smtp_to}"],
                "senderIP": "209.85.220.41",
                "subject": "Weekly team meeting notes",
                "spamScore": 5,
                "phishScore": 0,
                "classification": "",
                "quarantineRule": "",
                "quarantineFolder": "",
                "clusterId": "proofpointdedicated1",
                "policyRoutes": ["default_inbound"],
                "modulesRun": ["spam", "pdr", "url-defense"],
                "threatsInfoMap": [],
                "headerFrom": "{smtp_from}",
                "headerReplyTo": "{smtp_from}",
                "impostorScore": 0,
                "malwareScore": 0,
                "eventTypeString": "deliver",
            },
        },
        {
            "severity": "info",
            "title_template": "Proofpoint TAP: Blocked SPAM — external → {smtp_to}",
            "payload_template": {
                "messageTime": "{timestamp}",
                "fromAddress": ["noreply@promo-example.com"],
                "toAddresses": ["{smtp_to}"],
                "senderIP": "198.51.100.42",
                "subject": "Congratulations! You've been selected",
                "spamScore": 92,
                "phishScore": 12,
                "classification": "spam",
                "quarantineRule": "spam_block",
                "quarantineFolder": "Spam",
                "threatsInfoMap": [],
                "eventTypeString": "block",
            },
        },
    ],

    # ── Google Workspace ─────────────────────────────────────────────────────
    "google_workspace": [
        {
            "severity": "info",
            "title_template": "Google Workspace: Gmail.MessageReceived — {username}",
            "payload_template": {
                "kind": "admin#reports#activity",
                "id.time": "{timestamp}",
                "id.uniqueQualifier": "AEnB2UqW65qgK8gH9iJ0kL",
                "id.applicationName": "gmail",
                "id.customerId": "C01234abc",
                "actor.callerType": "USER",
                "actor.email": "{email}",
                "actor.profileId": "123456789",
                "ownerDomain": "{domain}",
                "ipAddress": "{src_ip}",
                "events": [
                    {
                        "type": "access",
                        "name": "EMAIL_READ",
                        "parameters": [
                            {"name": "message_id", "value": "1234567890abcdef"},
                            {"name": "actor_email", "value": "{email}"},
                        ],
                    }
                ],
            },
        },
        {
            "severity": "info",
            "title_template": "Google Workspace: Drive.FileViewed — {username}",
            "payload_template": {
                "kind": "admin#reports#activity",
                "id.time": "{timestamp}",
                "id.applicationName": "drive",
                "id.customerId": "C01234abc",
                "actor.callerType": "USER",
                "actor.email": "{email}",
                "ownerDomain": "{domain}",
                "ipAddress": "{src_ip}",
                "events": [
                    {
                        "type": "access",
                        "name": "VIEW",
                        "parameters": [
                            {"name": "doc_id", "value": "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"},
                            {"name": "doc_title", "value": "Q4 Planning Document"},
                            {"name": "doc_type", "value": "spreadsheet"},
                        ],
                    }
                ],
            },
        },
        {
            "severity": "info",
            "title_template": "Google Workspace: Admin.CHANGE_APPLICATION_SETTING — {username}",
            "payload_template": {
                "kind": "admin#reports#activity",
                "id.time": "{timestamp}",
                "id.applicationName": "admin",
                "id.customerId": "C01234abc",
                "actor.callerType": "USER",
                "actor.email": "{email}",
                "ownerDomain": "{domain}",
                "ipAddress": "{src_ip}",
                "events": [
                    {
                        "type": "account_settings",
                        "name": "CHANGE_APPLICATION_SETTING",
                        "parameters": [
                            {"name": "application_name", "value": "Gmail"},
                            {"name": "setting_name", "value": "Email auto-forwarding"},
                            {"name": "new_value", "value": "DISABLED"},
                        ],
                    }
                ],
            },
        },
    ],

    # ── Mimecast ─────────────────────────────────────────────────────────────
    "mimecast": [
        {
            "severity": "info",
            "title_template": "Mimecast: Email accepted — {smtp_from} → {smtp_to}",
            "payload_template": {
                "datetime": "{timestamp}",
                "acc": "C0A0",
                "aCode": "accepted",
                "aType": "Process",
                "senderAddress": "{smtp_from}",
                "recipientAddress": "{smtp_to}",
                "subject": "Team standup notes",
                "direction": "Inbound",
                "spamDetectionLevel": 0,
                "attachmentCount": 0,
                "senderIP": "209.85.220.41",
                "type": "receipt",
            },
        },
    ],
}
