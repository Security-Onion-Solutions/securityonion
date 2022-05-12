from io import StringIO
import sys
from unittest.mock import patch, MagicMock
from virustotal import virustotal
import unittest


class TestVirusTotalMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                virustotal.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once_with(2)

    def test_main_success(self):
        output = {"foo": "bar"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('virustotal.virustotal.analyze', new=MagicMock(return_value=output)) as mock:
                sys.argv = ["cmd", "input"]
                virustotal.main()
                expected = '{"foo": "bar"}\n'
                self.assertEqual(mock_stdout.getvalue(), expected)
                mock.assert_called_once()

    def test_checkConfigRequirements(self):
        conf = {"not_a_key": "abcd12345"}
        with self.assertRaises(SystemExit) as cm:
            virustotal.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_buildHeaders(self):
        result = virustotal.buildHeaders({"api_key": "xyz"})
        self.assertEqual("xyz", result["x-apikey"])

    def test_sendReq(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            meta = {}
            conf = {"base_url": "myurl="}
            response = virustotal.sendReq(conf=conf, meta=meta, payload="mypayload", headers={"x-apikey": "xyz"})
            mock.assert_called_once_with("GET", "myurl=mypayload", headers={"x-apikey": "xyz"})
            self.assertIsNotNone(response)

    def test_prepareResults_timeout(self):
        raw = {"data": [{"attributes": {"last_analysis_stats": {
            "harmless": 1,
            "malicious": 0,
            "suspicious": 0,
            "undetected": 1,
            "timeout": 1
          }}}, {"attributes": {"last_analysis_stats": {
            "harmless": 7,
            "malicious": 0,
            "suspicious": 0,
            "undetected": 11,
            "timeout": 0
          }}}]}
        results = virustotal.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "timeout")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_ok_multiple(self):
        raw = {"data": [{"attributes": {"last_analysis_stats": {
            "harmless": 1,
            "malicious": 0,
            "suspicious": 0,
            "undetected": 0,
            "timeout": 0
          }}}, {"attributes": {"last_analysis_stats": {
            "harmless": 7,
            "malicious": 0,
            "suspicious": 0,
            "undetected": 11,
            "timeout": 0
          }}}]}
        results = virustotal.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "harmless")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_sus_multiple(self):
        raw = {"data": [{"attributes": {"last_analysis_stats": {
            "harmless": 10,
            "malicious": 0,
            "suspicious": 2,
            "undetected": 0,
            "timeout": 0
          }}}, {"attributes": {"last_analysis_stats": {
            "harmless": 76,
            "malicious": 0,
            "suspicious": 1,
            "undetected": 11,
            "timeout": 0
          }}}]}
        results = virustotal.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "suspicious")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_threat_multiple(self):
        raw = {"data": [{"attributes": {"last_analysis_stats": {
            "harmless": 1,
            "malicious": 0,
            "suspicious": 0,
            "undetected": 0,
            "timeout": 0
          }}}, {"attributes": {"last_analysis_stats": {
            "harmless": 76,
            "malicious": 5,
            "suspicious": 1,
            "undetected": 11,
            "timeout": 0
          }}}]}
        results = virustotal.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "malicious")
        self.assertEqual(results["status"], "threat")

    def test_prepareResults_threat(self):
        raw = {"data": [{"attributes": {"last_analysis_stats": {
            "harmless": 76,
            "malicious": 5,
            "suspicious": 1,
            "undetected": 11,
            "timeout": 0
          }}}]}
        results = virustotal.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "malicious")
        self.assertEqual(results["status"], "threat")

    def test_prepareResults_error(self):
        raw = {}
        results = virustotal.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_analyze(self):
        output = {"data": [{"attributes": {"last_analysis_stats": {
            "harmless": 0,
            "malicious": 0,
            "suspicious": 0,
            "undetected": 1,
            "timeout": 0
          }}}]}
        artifactInput = '{"value":"foo","artifactType":"url"}'
        conf = {"api_key": "xyz"}
        with patch('virustotal.virustotal.sendReq', new=MagicMock(return_value=output)) as mock:
            results = virustotal.analyze(conf, artifactInput)
            self.assertEqual(results["summary"], "harmless")
            mock.assert_called_once()
