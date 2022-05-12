from io import StringIO
import sys
from unittest.mock import patch, MagicMock
from emailrep import emailrep
import unittest


class TestEmailRepMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                emailrep.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once_with(2)

    def test_main_success(self):
        output = {"foo": "bar"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('emailrep.emailrep.analyze', new=MagicMock(return_value=output)) as mock:
                sys.argv = ["cmd", "input"]
                emailrep.main()
                expected = '{"foo": "bar"}\n'
                self.assertEqual(mock_stdout.getvalue(), expected)
                mock.assert_called_once()

    def test_checkConfigRequirements_not_present(self):
        conf = {"not_a_file_path": "blahblah"}
        with self.assertRaises(SystemExit) as cm:
            emailrep.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_sendReq(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            meta = {}
            conf = {"base_url": "https://myurl/", "api_key": "abcd1234"}
            email = "test@abc.com"
            response = emailrep.sendReq(conf=conf, meta=meta, email=email)
            mock.assert_called_once_with("GET", headers={"Key": "abcd1234"}, url="https://myurl/test@abc.com")
            self.assertIsNotNone(response)

    def test_prepareResults_invalidEmail(self):
        raw = {"status": "fail", "reason": "invalid email"}
        results = emailrep.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "invalid_input")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_not_suspicious(self):
        raw = {"email": "notsus@domain.com", "reputation": "high", "suspicious": False, "references": 21, "details": {"blacklisted": False, "malicious_activity": False, "profiles": ["twitter"]}}
        results = emailrep.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "harmless")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_suspicious(self):
        raw = {"email": "sus@domain.com", "reputation": "none", "suspicious": True, "references": 0, "details": {"blacklisted": False, "malicious_activity": False, "profiles": []}}
        results = emailrep.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "suspicious")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_exceeded_limit(self):
        raw = {"status": "fail", "reason": "exceeded daily limit. please wait 24 hrs or visit emailrep.io/key for an api key."}
        results = emailrep.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "excessive_usage")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_error(self):
        raw = {}
        results = emailrep.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_analyze(self):
        output = {"email": "sus@domain.com", "reputation": "none", "suspicious": True, "references": 0, "details": {"blacklisted": False, "malicious_activity": False, "profiles": []}}
        artifactInput = '{"value":"sus@domain.com","artifactType":"email"}'
        conf = {"base_url": "myurl/", "api_key": "abcd1234"}
        with patch('emailrep.emailrep.sendReq', new=MagicMock(return_value=output)) as mock:
            results = emailrep.analyze(conf, artifactInput)
            self.assertEqual(results["summary"], "suspicious")
            mock.assert_called_once()
