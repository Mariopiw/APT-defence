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
