from io import StringIO
import sys
from unittest.mock import patch, MagicMock
from pulsedive import pulsedive
import unittest


class TestVirusTotalMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                pulsedive.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once_with(2)

    def test_main_success(self):
        output = {"foo": "bar"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('pulsedive.pulsedive.analyze', new=MagicMock(return_value=output)) as mock:
                sys.argv = ["cmd", "input"]
                pulsedive.main()
                expected = '{"foo": "bar"}\n'
                self.assertEqual(mock_stdout.getvalue(), expected)
                mock.assert_called_once()

    def test_checkConfigRequirements(self):
        conf = {"not_a_key": "abcd12345"}
        with self.assertRaises(SystemExit) as cm:
            pulsedive.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_buildReq_domain(self):
        conf = {"api_key": "xyz", "base_url": "https://myurl"}
        artifactType = "domain"
        artifactValue = "pulsedive.com"
        result = pulsedive.buildReq(conf, artifactType, artifactValue)
        self.assertEqual("https://myurl/info.php", result[0])
        self.assertEqual({"key": "xyz", "indicator": "pulsedive.com"}, result[1])

    def test_buildReq_uri_path(self):
        conf = {"api_key": "xyz", "base_url": "https://myurl"}
        artifactType = "uri_path"
        artifactValue = "/main.php"
        result = pulsedive.buildReq(conf, artifactType, artifactValue)
        self.assertEqual("https://myurl/explore.php", result[0])
        self.assertEqual({"key": "xyz", "q": "http.location=/main.php", "limit": 100}, result[1])

    def test_sendReq(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            url = 'https://myurl/api/'
            params = {"key": "abcd1234", "q": "http.location=/main.php", "limit": 100}
            response = pulsedive.sendReq(url=url, params=params)
            mock.assert_called_once_with("GET", "https://myurl/api/", params={"key": "abcd1234", "q": "http.location=/main.php", "limit": 100})
            self.assertIsNotNone(response)

    def test_prepareResults_risk_high(self):
        raw = {"results": [{"risk": "high"}]}
        results = pulsedive.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "malicious")
        self.assertEqual(results["status"], "threat")

    def test_prepareResults_risk_med(self):
        raw = {"results": [{"risk": "medium"}]}
        results = pulsedive.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "suspicious")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_risk_low(self):
        raw = {"results": [{"risk": "low"}]}
        results = pulsedive.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "harmless")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_risk_none(self):
        raw = {"results": [{"risk": "none"}]}
        results = pulsedive.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "harmless")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_risk_unknown(self):
        raw = {"results": [{"risk": "unknown"}]}
        results = pulsedive.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "")
        self.assertEqual(results["status"], "unknown")

    def test_prepareResults_no_results(self):
        raw = {"results": []}
        results = pulsedive.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "no_results")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_risk_none_indicator(self):
        raw = {"iid": "1234", "risk": "none"}
        results = pulsedive.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "harmless")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_indicator_not_Found(self):
        raw = {"error": "Indicator not found."}
        results = pulsedive.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "no_results")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_error(self):
        raw = {}
        results = pulsedive.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_analyze(self):
        output = {"results": [{"risk": "low"}]}
        artifactInput = '{"value":"chrome","artifactType":"user-agent"}'
        conf = {"api_key": "xyz", "base_url": "https://myurl"}
        with patch('pulsedive.pulsedive.sendReq', new=MagicMock(return_value=output)) as mock:
            results = pulsedive.analyze(conf, artifactInput)
            self.assertEqual(results["summary"], "harmless")
            mock.assert_called_once()
