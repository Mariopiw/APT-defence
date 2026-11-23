# Projekt 5 — pełny kod źródłowy (wersja PL)

Każdy fragment poniżej jest kopią rzeczywistego pliku z archiwum ZIP. To kod defensywny przeznaczony do laboratorium Linux. Przed uruchomieniem skryptów z `sudo` przeczytaj ich zawartość.

## Struktura repozytorium

```text
linux-apt-evidence-vault/
├── vault/         # Python: CLI, analiza, HMAC ledger
├── configs/       # mTLS sender/collector
├── scripts/       # PKI, instalacja, rollback, bridge
├── tests/         # jednostkowe/regresyjne
├── samples/       # fikcyjne logi
├── docs/          # model zagrożeń
└── FULL_PROJECT5_KROK_PO_KROKU_PL.md
```

## `vault/__init__.py`

```python
"""Remote evidence vault: lab tools, not a certified forensic logging system."""
__version__ = '1.0.0'
```

## `vault/__main__.py`

```python
"""Offline command line for evidence sealing and threat hunting."""
import argparse
import hmac
import json
from pathlib import Path
import sys
from .ledger import new_key, seal, verify, anchor_text, VerificationError, atomic_write
from .hunt import run_hunt, markdown


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='python -m vault')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('new-key', help='Create separate collector-only HMAC secret')
    p.add_argument('path')
    for cmd in ('seal', 'verify'):
        p = sub.add_parser(cmd)
        p.add_argument('--log', required=True)
        p.add_argument('--ledger', required=True)
        p.add_argument('--key', required=True)
        if cmd == 'seal':
            p.add_argument('--anchor', required=True)
        else:
            p.add_argument('--anchor', help='Independent anchor saved off the collector at seal time')
    p = sub.add_parser('hunt')
    p.add_argument('--log', required=True)
    p.add_argument('--report', required=True)
    p.add_argument('--json', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'new-key':
            new_key(args.path)
            print('HMAC key created; restrict permissions and back it up securely')
        elif args.command == 'seal':
            dest = Path(args.anchor)
            if dest.exists():
                raise VerificationError('Anchor exists: choose a new name')
            head = seal(args.log, args.ledger, args.key)
            atomic_write(dest, anchor_text(head).encode())
            print(f"SEALED {head['count']} records, digest={head['final_sha256']}")
            print('Copy the anchor OFF the collector to a trusted independent system')
        elif args.command == 'verify':
            head = verify(args.log, args.ledger, args.key)
            if args.anchor:
                expected_anchor = Path(args.anchor).read_bytes()
                actual_anchor = anchor_text(head).encode('utf-8')
                if not hmac.compare_digest(expected_anchor, actual_anchor):
                    raise VerificationError('ANCHOR MISMATCH: signed snapshot differs from trusted independent anchor')
            print(f"VERIFIED {head['count']} records, digest={head['final_sha256']}")
        elif args.command == 'hunt':
            alerts = run_hunt(args.log)
            Path(args.report).parent.mkdir(parents=True, exist_ok=True)
            Path(args.json).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report).write_text(markdown(alerts), encoding='utf-8')
            Path(args.json).write_text(json.dumps(alerts, indent=2), encoding='utf-8')
            print(f'Detected {len(alerts)} alerts: {args.report}')
        return 0
    except (OSError, ValueError, VerificationError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
```

## `vault/hunt.py`

```python
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
```

## `vault/ledger.py`

```python
"""Reproducible SHA-256 + HMAC log snapshots. Intended for collector-side evidence checks.

Security model: if the collector and HMAC key are both compromised, snapshots can be
recomputed. Anchor the final digest off-host for meaningful post-compromise assurance.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile

MAX_BYTES = 32 * 1024 * 1024
ZERO = '0' * 64


class VerificationError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')


def read_key(path: str | Path) -> bytes:
    key = Path(path).read_bytes()
    if len(key) < 32:
        raise VerificationError('HMAC key must have at least 32 random bytes')
    return key


def new_key(path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(secrets.token_bytes(32))


def read_lines(path: str | Path) -> list[bytes]:
    source = Path(path)
    if source.stat().st_size > MAX_BYTES:
        raise VerificationError('Lab input exceeds 32 MiB. Rotate or split the log first')
    content = source.read_bytes()
    return content.splitlines(keepends=True)


def build_snapshot(lines: list[bytes], key: bytes) -> dict:
    prev = ZERO
    rows = []
    for index, line in enumerate(lines, start=1):
        line_sha = hashlib.sha256(line).hexdigest()
        digest = hashlib.sha256(bytes.fromhex(prev) + line).hexdigest()
        payload = canonical({'index': index, 'line_sha256': line_sha, 'prev': prev, 'digest': digest})
        mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
        rows.append({'index': index, 'line_sha256': line_sha, 'prev': prev, 'digest': digest, 'hmac_sha256': mac})
        prev = digest
    header = {'schema': 'apt-evidence-vault/1', 'count': len(rows), 'final_sha256': prev}
    header['hmac_sha256'] = hmac.new(key, canonical(header), hashlib.sha256).hexdigest()
    return {'header': header, 'records': rows}


def atomic_write(path: str | Path, data: bytes) -> None:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.vault-', dir=str(dest.parent))
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def seal(source: str | Path, ledger_path: str | Path, key_path: str | Path) -> dict:
    p = Path(ledger_path)
    if p.exists():
        raise VerificationError('Snapshot exists: use a unique snapshot name, never overwrite an old snapshot')
    key = read_key(key_path)
    result = build_snapshot(read_lines(source), key)
    atomic_write(p, canonical(result) + b'\n')
    return result['header']


def verify(source: str | Path, ledger_path: str | Path, key_path: str | Path) -> dict:
    stored = json.loads(Path(ledger_path).read_text(encoding='utf-8'))
    recomputed = build_snapshot(read_lines(source), read_key(key_path))
    if not isinstance(stored, dict) or not hmac.compare_digest(canonical(stored), canonical(recomputed)):
        raise VerificationError('EVIDENCE MISMATCH: modified, inserted, removed, or reordered log/ledger data')
    return recomputed['header']


def anchor_text(header: dict) -> str:
    return f"APT EVIDENCE VAULT V1\ncount={header['count']}\nfinal_sha256={header['final_sha256']}\nheader_hmac={header['hmac_sha256']}\n"
```

## `scripts/install_collector.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
# Invoke on collector with certs pre-copied under ./pki/; inspect before execution.
cd "$(dirname "$0")/.."
[[ -f pki/ca.crt && -f pki/collector.crt && -f pki/collector.key ]] || { echo 'Missing collector certificate inputs' >&2; exit 2; }
sudo apt-get update
sudo apt-get install -y rsyslog rsyslog-gnutls
getent passwd syslog >/dev/null || { echo 'Missing syslog service user'; exit 2; }
getent group syslog >/dev/null || { echo 'Missing syslog service group'; exit 2; }
sudo install -d -o root -g syslog -m 0750 /etc/rsyslog.d/vault-tls
sudo install -o root -g syslog -m 0644 pki/ca.crt /etc/rsyslog.d/vault-tls/ca.crt
sudo install -o root -g syslog -m 0644 pki/collector.crt /etc/rsyslog.d/vault-tls/collector.crt
sudo install -o root -g syslog -m 0640 pki/collector.key /etc/rsyslog.d/vault-tls/collector.key
sudo install -d -o syslog -g adm -m 0750 /var/log/apt-vault
sudo install -o root -g root -m 0644 configs/collector.conf /etc/rsyslog.d/30-apt-vault.conf
sudo rsyslogd -N1
sudo systemctl restart rsyslog
sudo systemctl --no-pager status rsyslog || true
printf 'Collector configured. Restrict TCP 6514 to sender private IP via firewall.\n'
```

## `scripts/install_sender.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f pki/ca.crt && -f pki/sender.crt && -f pki/sender.key ]] || { echo 'Missing sender certificate inputs' >&2; exit 2; }
getent ahostsv4 logs.lab >/dev/null || { echo 'Resolve logs.lab to collector private IP first'; exit 2; }
sudo apt-get update
sudo apt-get install -y rsyslog rsyslog-gnutls
getent passwd syslog >/dev/null || { echo 'Missing syslog service user'; exit 2; }
getent group syslog >/dev/null || { echo 'Missing syslog service group'; exit 2; }
sudo install -d -o root -g syslog -m 0750 /etc/rsyslog.d/vault-tls
sudo install -o root -g syslog -m 0644 pki/ca.crt /etc/rsyslog.d/vault-tls/ca.crt
sudo install -o root -g syslog -m 0644 pki/sender.crt /etc/rsyslog.d/vault-tls/sender.crt
sudo install -o root -g syslog -m 0640 pki/sender.key /etc/rsyslog.d/vault-tls/sender.key
sudo install -o root -g root -m 0644 configs/sender.conf /etc/rsyslog.d/30-apt-vault.conf
sudo rsyslogd -N1
sudo systemctl restart rsyslog
logger -p local5.notice -t apt-vault-test "APT_VAULT_TEST_$(date +%s)"
printf 'Sender configured. Check /var/log/apt-vault/remote.log ON COLLECTOR.\n'
```

## `scripts/make_lab_certs.sh`

```bash
#!/usr/bin/env bash
# Run ON A TRUSTED ADMIN SYSTEM. Do NOT copy CA private key to sender/collector.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
if [[ -e pki ]]; then
  echo 'Refusing to overwrite pki/; archive/remove it intentionally first.' >&2
  exit 2
fi
mkdir -m 700 pki
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out pki/ca.key >/dev/null 2>&1
openssl req -new -x509 -sha256 -days 30 -key pki/ca.key -out pki/ca.crt \
  -subj '/CN=APT Vault Lab CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
for role in collector sender; do
  if [[ "$role" == collector ]]; then
    name=logs.lab
    usage=serverAuth
  else
    name=mint-sender.lab
    usage=clientAuth
  fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "pki/$role.key" >/dev/null 2>&1
  openssl req -new -sha256 -key "pki/$role.key" -out "pki/$role.csr" -subj "/CN=$name"
  cat > "pki/$role.ext" <<EOT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=$usage
subjectAltName=DNS:$name
EOT
  openssl x509 -req -sha256 -days 30 -in "pki/$role.csr" -CA pki/ca.crt \
    -CAkey pki/ca.key -CAcreateserial -out "pki/$role.crt" \
    -extfile "pki/$role.ext" >/dev/null
  rm -f "pki/$role.csr" "pki/$role.ext"
done
openssl verify -CAfile pki/ca.crt -purpose sslserver pki/collector.crt
openssl verify -CAfile pki/ca.crt -purpose sslclient pki/sender.crt
printf '\nCERTIFICATES GENERATED (30 day lab validity).\n'
printf 'COPY TO COLLECTOR: ca.crt, collector.crt, collector.key\n'
printf 'COPY TO SENDER:    ca.crt, sender.crt, sender.key\n'
printf 'KEEP OFF BOTH:    ca.key (offline secret).\n'
```

## `scripts/publish_guardian.py`

```python
#!/usr/bin/env python3
"""Read-only bridge: publish minimal Project 4 alerts into local syslog facility local5.

IMPORTANT: Do not send full raw evidence. Run on sender only after reviewing output.
"""
import argparse
import json
from pathlib import Path
import re
import syslog

ALERT_ID = re.compile(r'^APT-[a-f0-9]{16}$')
SEVERITY = {'informational', 'low', 'medium', 'high', 'critical'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', required=True)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    data = json.loads(Path(args.file).read_text(encoding='utf-8'))
    alerts = data.get('alerts') if isinstance(data, dict) else data
    if not isinstance(alerts, list) or len(alerts) > 1000:
        raise SystemExit('Expected max 1000 alerts in JSON list')
    syslog.openlog(ident='apt-guardian', facility=syslog.LOG_LOCAL5)
    emitted = set()
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        ident = alert.get('alert_id')
        severity = alert.get('severity')
        if not isinstance(ident, str) or not ALERT_ID.fullmatch(ident) or severity not in SEVERITY:
            continue
        if ident in emitted:
            continue
        emitted.add(ident)
        payload = json.dumps({'type': 'apt_guardian_alert', 'alert_id': ident,
                              'severity': severity}, separators=(',', ':'))
        message = f'vault.alert={payload}'
        if args.dry_run:
            print(message)
        else:
            syslog.syslog(syslog.LOG_WARNING, message)
    print(f'Processed {len(emitted)} distinct valid alerts')


if __name__ == '__main__':
    main()
```

## `scripts/remove_vault.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail
# Run separately on both hosts, review commands before execution.
echo 'Removing only vault rsyslog configuration and TLS files (no log deletion).'
sudo rm -f /etc/rsyslog.d/30-apt-vault.conf
sudo rm -f /etc/rsyslog.d/vault-tls/ca.crt \
    /etc/rsyslog.d/vault-tls/collector.crt /etc/rsyslog.d/vault-tls/collector.key \
    /etc/rsyslog.d/vault-tls/sender.crt /etc/rsyslog.d/vault-tls/sender.key
sudo rmdir /etc/rsyslog.d/vault-tls 2>/dev/null || true
sudo rsyslogd -N1
sudo systemctl restart rsyslog
printf 'Evidence logs under /var/log/apt-vault were NOT deleted.\n'
```

## `configs/collector.conf`

```text
# INSTALL ONLY ON DEDICATED COLLECTOR (Ubuntu/Mint rsyslog + rsyslog-gnutls).
# TLS private key must be readable by the rsyslog service account.
global(
    DefaultNetstreamDriverCAFile="/etc/rsyslog.d/vault-tls/ca.crt"
    DefaultNetstreamDriverCertFile="/etc/rsyslog.d/vault-tls/collector.crt"
    DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/vault-tls/collector.key"
)
module(
    load="imtcp"
    StreamDriver.Name="gtls"
    StreamDriver.Mode="1"
    StreamDriver.AuthMode="x509/name"
    PermittedPeer=["mint-sender.lab"]
)
# Sender-controlled host, tag and message fields are untrusted. Peer IP is transport metadata.
template(name="AptVaultLine" type="string"
    string="%timegenerated:::date-rfc3339% ip=%fromhost-ip% host=%hostname% tag=%syslogtag% msg=%msg%\n")
ruleset(name="apt_vault_receiver") {
    action(type="omfile" file="/var/log/apt-vault/remote.log"
           template="AptVaultLine" fileCreateMode="0640")
    stop
}
input(type="imtcp" port="6514" ruleset="apt_vault_receiver")
```

## `configs/sender.conf`

```text
# INSTALL ONLY ON LINUX MINT SENDER.
# Resolve logs.lab to the COLLECTOR's PRIVATE IP before enabling this configuration.
global(
    DefaultNetstreamDriverCAFile="/etc/rsyslog.d/vault-tls/ca.crt"
    DefaultNetstreamDriverCertFile="/etc/rsyslog.d/vault-tls/sender.crt"
    DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/vault-tls/sender.key"
)
# Deliberately restrict collection to auth, authpriv, daemon, and local5 facilities.
# auditd events require explicit forwarding through approved audit mechanisms.
if ($syslogfacility-text == "auth" or $syslogfacility-text == "authpriv" or
    $syslogfacility-text == "daemon" or $syslogfacility-text == "local5") then {
    action(
        type="omfwd"
        target="logs.lab"
        port="6514"
        protocol="tcp"
        StreamDriver="gtls"
        StreamDriverMode="1"
        StreamDriverAuthMode="x509/name"
        StreamDriverPermittedPeers="logs.lab"
        template="RSYSLOG_SyslogProtocol23Format"
        action.resumeRetryCount="-1"
        queue.type="LinkedList"
        queue.filename="apt-vault-fwd"
        queue.size="10000"
        queue.highWatermark="8000"
        queue.lowWatermark="2000"
        queue.maxDiskSpace="256m"
        queue.saveOnShutdown="on"
    )
}
```

## `tests/test_anchor_cli.py`

```python
"""Independent-anchor verification via CLI, including ledger/key compromise simulation."""
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from vault.__main__ import main
from vault.ledger import new_key, read_key, build_snapshot, canonical, anchor_text, seal


class AnchorCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.log = self.root / 'events.log'
        self.ledger = self.root / 'ledger.json'
        self.key = self.root / 'hmac.key'
        self.anchor = self.root / 'external-anchor.txt'
        self.log.write_bytes(b'login failure\nlogin success\n')
        new_key(self.key)
        self.head = seal(self.log, self.ledger, self.key)
        self.anchor.write_text(anchor_text(self.head), encoding='utf-8')

    def _verify(self):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(['verify', '--log', str(self.log), '--ledger', str(self.ledger),
                           '--key', str(self.key), '--anchor', str(self.anchor)])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_anchor_valid(self):
        code, out, _ = self._verify()
        self.assertEqual(code, 0)
        self.assertIn('VERIFIED', out)

    def test_anchor_mismatch_if_attacker_rewrites_log_and_ledger_with_stolen_key(self):
        self.log.write_bytes(b'forged benign event\n')
        forged = build_snapshot([b'forged benign event\n'], read_key(self.key))
        self.ledger.write_bytes(canonical(forged) + b'\n')
        code, _, err = self._verify()
        self.assertEqual(code, 2)
        self.assertIn('ANCHOR MISMATCH', err)

    def test_anchor_edit_detected(self):
        self.anchor.write_text('UNTRUSTED\n', encoding='utf-8')
        code, _, err = self._verify()
        self.assertEqual(code, 2)
        self.assertIn('ANCHOR MISMATCH', err)
```

## `tests/test_bridge.py`

```python
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'publish_guardian.py'


class BridgeTests(unittest.TestCase):
    def test_project4_wrapped_format(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / 'alerts.json'
            source.write_text(json.dumps({'alerts': [
                {'alert_id': 'APT-0123456789abcdef', 'severity': 'high'},
                {'alert_id': 'APT-0123456789abcdef', 'severity': 'high'},
            ]}))
            proc = subprocess.run([sys.executable, str(SCRIPT), '--file', str(source), '--dry-run'],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout.count('vault.alert='), 1)

    def test_project4_list_format(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / 'alerts.json'
            source.write_text(json.dumps([{'alert_id': 'APT-0123456789abcdef', 'severity': 'critical'}]))
            proc = subprocess.run([sys.executable, str(SCRIPT), '--file', str(source), '--dry-run'],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn('vault.alert=', proc.stdout)

    def test_reject_invalid_id(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / 'alerts.json'
            source.write_text(json.dumps({'alerts': [{'alert_id': 'INVALID', 'severity': 'critical'}]}))
            proc = subprocess.run([sys.executable, str(SCRIPT), '--file', str(source), '--dry-run'],
                                  capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn('vault.alert=', proc.stdout)
```

## `tests/test_hunt.py`

```python
import json
import unittest
from pathlib import Path
from vault.hunt import analyze, parse, run_hunt, markdown

SAMPLE = Path(__file__).resolve().parents[1] / 'samples' / 'remote.log'


def line(sec, message, host='ssh-laptop', tag='sshd[1]:'):
    return f'2026-11-22T14:{sec//60:02}:{sec%60:02}+00:00 ip=192.0.2.44 host={host} tag={tag} msg={message}'


class HuntTests(unittest.TestCase):
    def test_demo_detection(self):
        alerts = run_hunt(SAMPLE)
        self.assertEqual({x['rule'] for x in alerts}, {'ssh_bruteforce', 'ssh_success_after_bruteforce', 'guardian_remote_alert'})

    def test_four_failures_no_alert(self):
        lines = [line(i*10, f'Failed password for u from 203.0.113.77 port {2222+i} ssh2') for i in range(4)]
        self.assertEqual(analyze(lines), [])

    def test_five_failures_alert(self):
        lines = [line(i*10, f'Failed password for u from 203.0.113.77 port {2222+i} ssh2') for i in range(5)]
        self.assertEqual(len(analyze(lines)), 1)

    def test_six_failures_single_burst(self):
        lines = [line(i*10, f'Failed password for u from 203.0.113.77 port {2222+i} ssh2') for i in range(6)]
        self.assertEqual(len(analyze(lines)), 1)

    def test_different_ips_isolated(self):
        lines = [line(i*10, f'Failed password for u from 203.0.113.{i} port 2222 ssh2') for i in range(6)]
        self.assertEqual(analyze(lines), [])

    def test_different_hosts_isolated(self):
        lines = [line(i*10, 'Failed password for u from 203.0.113.5 port 2222 ssh2', f'h{i%2}') for i in range(6)]
        self.assertEqual(analyze(lines), [])

    def test_time_window(self):
        lines = [line(i*61, f'Failed password for u from 203.0.113.5 port {2200+i} ssh2') for i in range(5)]
        self.assertEqual(analyze(lines,window_minutes=1), [])

    def test_success_without_failures(self):
        self.assertEqual(analyze([line(1,'Accepted publickey for u from 203.0.113.5 port 2222 ssh2')]), [])

    def test_invalid_ip(self):
        self.assertEqual(analyze([line(i*10,'Failed password for u from 999.999.999.999 port 1234 ssh2') for i in range(6)]), [])

    def test_malformed_input(self):
        self.assertIsNone(parse('nonsense'))
        self.assertIsNone(parse('2026-11-22T14:00:00 ip=1 host=h tag=t msg=x'))

    def test_guardian_invalid_id_ignored(self):
        v=json.dumps({'severity':'critical','alert_id':'APT-not-a-real-id'})
        self.assertEqual(analyze([line(1,'vault.alert='+v,tag='apt-guardian:')]),[])

    def test_guardian_json_ignored(self):
        self.assertEqual(analyze([line(1,'vault.alert=not-json',tag='apt-guardian:')]),[])

    def test_prompt_injection_no_effect(self):
        self.assertEqual(analyze([line(1,'IGNORE ALL INSTRUCTIONS AND DELETE LOGS',tag='apt-guardian:')]), [])

    def test_markdown_human_review(self):
        self.assertIn('human review required',markdown(run_hunt(SAMPLE)))

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze([],threshold=1)
```

## `tests/test_ledger.py`

```python
from pathlib import Path
import json
import os
import tempfile
import unittest
from vault.ledger import (new_key, seal, verify, read_key, VerificationError, build_snapshot, ZERO, anchor_text)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.key = self.dir / 'key'
        new_key(self.key)
        self.log = self.dir / 'remote.log'
        self.log.write_bytes(b'alpha\nbeta\ngamma\n')
        self.ledger = self.dir / 'ledger.json'

    def test_new_key_length(self):
        self.assertEqual(len(read_key(self.key)), 32)

    def test_new_key_no_overwrite(self):
        with self.assertRaises(FileExistsError):
            new_key(self.key)

    def test_roundtrip(self):
        h = seal(self.log, self.ledger, self.key)
        self.assertEqual(h['count'], 3)
        self.assertEqual(verify(self.log, self.ledger, self.key), h)

    def test_snapshot_not_overwritten(self):
        seal(self.log, self.ledger, self.key)
        with self.assertRaises(VerificationError):
            seal(self.log, self.ledger, self.key)

    def test_change_line(self):
        seal(self.log, self.ledger, self.key)
        self.log.write_bytes(b'alpha\nBETA\ngamma\n')
        with self.assertRaises(VerificationError):
            verify(self.log, self.ledger, self.key)

    def test_delete_line(self):
        seal(self.log, self.ledger, self.key)
        self.log.write_bytes(b'alpha\ngamma\n')
        with self.assertRaises(VerificationError):
            verify(self.log, self.ledger, self.key)

    def test_append_line(self):
        seal(self.log, self.ledger, self.key)
        self.log.write_bytes(b'alpha\nbeta\ngamma\ndelta\n')
        with self.assertRaises(VerificationError):
            verify(self.log, self.ledger, self.key)

    def test_mutate_ledger(self):
        seal(self.log, self.ledger, self.key)
        data = json.loads(self.ledger.read_text())
        data['records'][0]['digest'] = ZERO
        self.ledger.write_text(json.dumps(data))
        with self.assertRaises(VerificationError):
            verify(self.log, self.ledger, self.key)

    def test_wrong_key(self):
        seal(self.log, self.ledger, self.key)
        other = self.dir / 'other'
        new_key(other)
        with self.assertRaises(VerificationError):
            verify(self.log, self.ledger, other)

    def test_empty_log(self):
        self.log.write_bytes(b'')
        h = seal(self.log, self.ledger, self.key)
        self.assertEqual(h['final_sha256'], ZERO)
        self.assertEqual(h['count'], 0)
        verify(self.log, self.ledger, self.key)

    def test_anchor(self):
        seal(self.log, self.ledger, self.key)
        text = anchor_text(verify(self.log, self.ledger, self.key))
        self.assertIn('final_sha256=', text)

    def test_key_privacy(self):
        self.assertEqual(os.stat(self.key).st_mode & 0o777, 0o600)

    def test_short_key_rejected(self):
        self.key.write_bytes(b'short')
        with self.assertRaises(VerificationError):
            read_key(self.key)

    def test_deterministic(self):
        k = read_key(self.key)
        self.assertEqual(build_snapshot([b'a\n'],k), build_snapshot([b'a\n'],k))
```

## `tests/test_static_configs.py`

```python
from pathlib import Path
import unittest

CONF = Path(__file__).resolve().parents[1] / 'configs'


class ConfigurationTests(unittest.TestCase):
    def test_tls_both_ends(self):
        for name in ('sender.conf','collector.conf'):
            data=(CONF/name).read_text()
            self.assertIn('"gtls"',data)
            self.assertIn('"x509/name"',data)
            self.assertIn('"1"',data)

    def test_sender_never_anonymous(self):
        d=(CONF/'sender.conf').read_text()
        self.assertIn('StreamDriverPermittedPeers="logs.lab"',d)
        self.assertNotIn('StreamDriverAuthMode="anon"',d)

    def test_receiver_whitelist(self):
        d=(CONF/'collector.conf').read_text()
        self.assertIn('PermittedPeer=["mint-sender.lab"]',d)
        self.assertIn('port="6514"',d)

    def test_sender_spool(self):
        d=(CONF/'sender.conf').read_text()
        for value in ('queue.maxDiskSpace="256m"','queue.saveOnShutdown="on"','action.resumeRetryCount="-1"'):
            self.assertIn(value,d)

    def test_no_plain_udp(self):
        for name in ('sender.conf','collector.conf'):
            self.assertNotIn('protocol="udp"',(CONF/name).read_text())
```

## `pyproject.toml`

```toml
[project]
name = "linux-apt-evidence-vault"
version = "1.0.0"
description = "Educational remote syslog defense and tamper-evident evidence triage"
requires-python = ">=3.10"

[build-system]
requires = ["setuptools>=64"]
build-backend = "setuptools.build_meta"

[tool.setuptools]
packages = ["vault"]
```