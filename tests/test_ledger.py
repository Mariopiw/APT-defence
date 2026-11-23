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
