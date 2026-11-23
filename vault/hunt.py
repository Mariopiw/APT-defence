"""Defensive triage on collector logs, with untrusted text treated as data."""
from __future__ import annotations
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re

STAMP = re.compile(r'^(?P<when>\S+) ip=(?P<peer>\S+) host=(?P<host>\S+) tag=(?P<tag>\S+) msg=(?P<msg>.*)$')
FAILED = re.compile(r'Failed password .*? from (?P<ip>[0-9a-fA-F:.]+) port \d+')
ACCEPTED = re.compile(r'Accepted (?:password|publickey) for (?P<user>[A-Za-z0-9_.-]+) from (?P<ip>[0-9a-fA-F:.]+) port \d+')
VALID_SEVERITY = {'critical', 'high', 'medium', 'low', 'informational'}


def parse(line: str) -> dict | None:
    match = STAMP.match(line.rstrip('\n'))
    if not match:
        return None
    data = match.groupdict()
    try:
        stamp = datetime.fromisoformat(data['when'].replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            return None
        data['timestamp'] = stamp.astimezone(timezone.utc)
        return data
    except ValueError:
        return None


def _alert(kind: str, severity: str, host: str, lines: list[dict]) -> dict:
    evidence = [{'timestamp': v['timestamp'].isoformat(), 'line_sha256': hashlib.sha256(v['raw'].encode('utf-8')).hexdigest()} for v in lines]
    key = hashlib.sha256(json.dumps({'kind': kind, 'host': host, 'evidence': evidence}, sort_keys=True).encode()).hexdigest()[:16]
    return {'alert_id': 'VAULT-' + key, 'rule': kind, 'severity': severity, 'host': host,
            'evidence': evidence, 'status': 'needs_human_review'}


def analyze(lines: list[str], *, threshold: int = 5, window_minutes: int = 5) -> list[dict]:
    if not 2 <= threshold <= 100 or not 1 <= window_minutes <= 120:
        raise ValueError('Invalid detection threshold/window')
    parsed = []
    for ln in lines:
        rec = parse(ln)
        if rec:
            rec['raw'] = ln.rstrip('\n')
            parsed.append(rec)
    parsed.sort(key=lambda x: x['timestamp'])
    failed: dict[tuple[str, str], deque] = defaultdict(deque)
    triggered: set[tuple[str, str]] = set()
    alerts = []
    for rec in parsed:
        host = rec['host']
        msg = rec['msg']
        match_failure = FAILED.search(msg)
        match_success = ACCEPTED.search(msg)
        if match_failure or match_success:
            ip = (match_failure or match_success).group('ip')
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            key = (host, ip)
            q = failed[key]
            while q and rec['timestamp'] - q[0]['timestamp'] > timedelta(minutes=window_minutes):
                q.popleft()
            if match_failure:
                q.append(rec)
                if len(q) >= threshold and key not in triggered:
                    alerts.append(_alert('ssh_bruteforce', 'high', host, list(q)[-threshold:]))
                    triggered.add(key)
                if len(q) < threshold:
                    triggered.discard(key)
            else:
                if len(q) >= threshold:
                    alerts.append(_alert('ssh_success_after_bruteforce', 'critical', host, list(q)[-threshold:] + [rec]))
                q.clear()
                triggered.discard(key)
        if rec['tag'].startswith('apt-guardian') and msg.startswith('vault.alert='):
            try:
                value = json.loads(msg[len('vault.alert='):])
                if (isinstance(value, dict) and value.get('severity') in VALID_SEVERITY
                        and re.fullmatch(r'APT-[a-f0-9]{16}', str(value.get('alert_id', '')))):
                    alerts.append(_alert('guardian_remote_alert', value['severity'], host, [rec]))
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
    return alerts


def run_hunt(path: str | Path) -> list[dict]:
    source = Path(path)
    if source.stat().st_size > 32 * 1024 * 1024:
        raise ValueError('Log exceeds lab processing limit of 32 MiB')
    return analyze(source.read_text(encoding='utf-8', errors='replace').splitlines())


def markdown(alerts: list[dict]) -> str:
    rows = ['# Remote APT Evidence — Triage Report', '', f'Alerts: **{len(alerts)}**', '',
            'These are detection hypotheses, not proof of compromise.', '']
    for a in alerts:
        rows.extend([f"## {a['alert_id']}", f"- Rule: `{a['rule']}`",
                     f"- Severity: `{a['severity']}`", f"- Host: `{a['host']}`",
                     f"- Evidence lines: {len(a['evidence'])}", '- Decision: **human review required**', ''])
    return '\n'.join(rows)
