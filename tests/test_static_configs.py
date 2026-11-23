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
