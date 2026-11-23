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
