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
