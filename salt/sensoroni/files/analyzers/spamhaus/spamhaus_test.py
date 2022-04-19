from io import StringIO
import dns
import sys
from unittest.mock import patch, MagicMock
from spamhaus import spamhaus
import unittest


class FakeAnswer:
    address = ''

    def __init__(self, ip='127.0.0.1'):
        self.address = ip

    def to_text(self):
        return str(self.address)


class TestSpamhausMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                spamhaus.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once_with(2)

    def test_main_success(self):
        output = {"foo": "bar"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('spamhaus.spamhaus.analyze', new=MagicMock(return_value=output)) as mock:
                sys.argv = ["cmd", "input"]
                spamhaus.main()
                expected = '{"foo": "bar"}\n'
                self.assertEqual(mock_stdout.getvalue(), expected)
                mock.assert_called_once()

    def test_resolve(self):
        with patch('dns.resolver.Resolver.resolve', new=MagicMock(return_value=MagicMock())) as mock:
            meta = {}
            conf = {"nameservers": ["1.2.3.4"], "lookup_host": "some.host"}
            response = spamhaus.resolve(config=conf, meta=meta, ip="127.0.0.1")
            mock.assert_called_once_with("1.0.0.127.some.host.")
            self.assertIsNotNone(response)

    def test_resolve_not_found(self):
        mock = MagicMock()
        mock.side_effect = dns.resolver.NXDOMAIN
        with patch('dns.resolver.Resolver.resolve', new=mock):
            meta = {}
            conf = {"nameservers": ["1.2.3.4"], "lookup_host": "some.host"}
            response = spamhaus.resolve(config=conf, meta=meta, ip="127.0.0.1")
            mock.assert_called_once_with("1.0.0.127.some.host.")
            self.assertIsNotNone(response)

    def test_prepareResults_ok_multiple(self):
        raw = [FakeAnswer("127.0.0.0"), FakeAnswer("127.0.0.1")]
        results = spamhaus.prepareResults(raw)
        self.assertEqual(results["response"], ['127.0.0.0', '127.0.0.1'])
        self.assertEqual(results["summary"], "harmless")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_failure2(self):
        raw = [FakeAnswer("127.255.255.252")]
        results = spamhaus.prepareResults(raw)
        self.assertEqual(results["response"], ['127.255.255.252'])
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_failure4(self):
        raw = [FakeAnswer("127.255.255.254")]
        results = spamhaus.prepareResults(raw)
        self.assertEqual(results["response"], ['127.255.255.254'])
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_excessive(self):
        raw = [FakeAnswer("127.255.255.255")]
        results = spamhaus.prepareResults(raw)
        self.assertEqual(results["response"], ['127.255.255.255'])
        self.assertEqual(results["summary"], "excessive_usage")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_sus_multiple(self):
        raw = [FakeAnswer("127.0.0.10"), FakeAnswer("127.0.0.11")]
        results = spamhaus.prepareResults(raw)
        self.assertEqual(results["response"], ['127.0.0.10', '127.0.0.11'])
        self.assertEqual(results["summary"], "suspicious")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_spam_multiple(self):
        raw = [FakeAnswer("127.0.0.2")]
        results = spamhaus.prepareResults(raw)
        self.assertEqual(results["response"], ['127.0.0.2'])
        self.assertEqual(results["summary"], "spam")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_threat_multiple(self):
        raw = [FakeAnswer("127.0.0.1"), FakeAnswer("127.0.0.4")]
        results = spamhaus.prepareResults(raw)
        self.assertEqual(results["response"], ['127.0.0.1', '127.0.0.4'])
        self.assertEqual(results["summary"], "malicious")
        self.assertEqual(results["status"], "threat")

    def test_prepareResults_threat(self):
        raw = [FakeAnswer("127.0.0.4")]
        results = spamhaus.prepareResults(raw)
        self.assertEqual(results["response"], ['127.0.0.4'])
        self.assertEqual(results["summary"], "malicious")
        self.assertEqual(results["status"], "threat")

    def test_prepareResults_error(self):
        raw = []
        results = spamhaus.prepareResults(raw)
        self.assertEqual(results["response"], [])
        self.assertEqual(results["summary"], "harmless")
        self.assertEqual(results["status"], "ok")

    def test_analyze(self):
        output = [FakeAnswer()]
        artifactInput = '{"value":"1.2.3.4","artifactType":"ip"}'
        with patch('spamhaus.spamhaus.resolve', new=MagicMock(return_value=output)) as mock:
            results = spamhaus.analyze({}, artifactInput)
            self.assertEqual(results["summary"], "harmless")
            mock.assert_called_once()
