from io import StringIO
import sys
from unittest.mock import patch, MagicMock
from greynoise import greynoise
import unittest


class TestGreynoiseMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                greynoise.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once_with(2)

    def test_main_success(self):
        output = {"foo": "bar"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('greynoise.greynoise.analyze', new=MagicMock(return_value=output)) as mock:
                sys.argv = ["cmd", "input"]
                greynoise.main()
                expected = '{"foo": "bar"}\n'
                self.assertEqual(mock_stdout.getvalue(), expected)
                mock.assert_called_once()

    def test_checkConfigRequirements_not_present(self):
        conf = {"not_a_file_path": "blahblah"}
        with self.assertRaises(SystemExit) as cm:
            greynoise.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_sendReq_community(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            meta = {}
            conf = {"base_url": "https://myurl/", "api_key": "abcd1234", "api_version": "community"}
            ip = "192.168.1.1"
            response = greynoise.sendReq(conf=conf, meta=meta, ip=ip)
            mock.assert_called_once_with("GET", headers={'key': 'abcd1234'}, url="https://myurl/v3/community/192.168.1.1")
            self.assertIsNotNone(response)

    def test_sendReq_investigate(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            meta = {}
            conf = {"base_url": "https://myurl/", "api_key": "abcd1234", "api_version": "investigate"}
            ip = "192.168.1.1"
            response = greynoise.sendReq(conf=conf, meta=meta, ip=ip)
            mock.assert_called_once_with("GET", headers={'key': 'abcd1234'}, url="https://myurl/v2/noise/context/192.168.1.1")
            self.assertIsNotNone(response)

    def test_sendReq_automate(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            meta = {}
            conf = {"base_url": "https://myurl/", "api_key": "abcd1234", "api_version": "automate"}
            ip = "192.168.1.1"
            response = greynoise.sendReq(conf=conf, meta=meta, ip=ip)
            mock.assert_called_once_with("GET", headers={'key': 'abcd1234'}, url="https://myurl/v2/noise/context/192.168.1.1")
            self.assertIsNotNone(response)

    def test_prepareResults_invalidIP(self):
        raw = {"message": "Request is not a valid routable IPv4 address"}
        results = greynoise.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "invalid_input")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_not_found(self):
        raw = {"ip": "192.190.1.1", "noise": "false", "riot": "false", "message": "IP not observed scanning the internet or contained in RIOT data set."}
        results = greynoise.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "no_results")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_benign(self):
        raw = {"ip": "8.8.8.8", "noise": "false", "riot": "true", "classification": "benign", "name": "Google Public DNS", "link": "https://viz.gn.io", "last_seen": "2022-04-26", "message": "Success"}
        results = greynoise.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "harmless")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_malicious(self):
        raw = {"ip": "121.142.87.218", "noise": "true", "riot": "false", "classification": "malicious", "name": "unknown", "link": "https://viz.gn.io", "last_seen": "2022-04-26", "message": "Success"}
        results = greynoise.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "malicious")
        self.assertEqual(results["status"], "threat")

    def test_prepareResults_unknown(self):
        raw = {"ip": "221.4.62.149", "noise": "true", "riot": "false", "classification": "unknown", "name": "unknown", "link": "https://viz.gn.io", "last_seen": "2022-04-26", "message": "Success"}
        results = greynoise.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "suspicious")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_unknown_message(self):
        raw = {"message": "unknown"}
        results = greynoise.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "unknown")
        self.assertEqual(results["status"], "info")

    def test_prepareResults_error(self):
        raw = {}
        results = greynoise.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_analyze(self):
        output = {"ip": "221.4.62.149", "noise": "true", "riot": "false", "classification": "unknown", "name": "unknown", "link": "https://viz.gn.io", "last_seen": "2022-04-26", "message": "Success"}
        artifactInput = '{"value":"221.4.62.149","artifactType":"ip"}'
        conf = {"base_url": "myurl/", "api_key": "abcd1234", "api_version": "community"}
        with patch('greynoise.greynoise.sendReq', new=MagicMock(return_value=output)) as mock:
            results = greynoise.analyze(conf, artifactInput)
            self.assertEqual(results["summary"], "suspicious")
            mock.assert_called_once()
