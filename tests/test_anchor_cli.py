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
