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
