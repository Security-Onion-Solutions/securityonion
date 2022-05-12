from io import StringIO
import sys
from unittest.mock import patch, MagicMock, PropertyMock, call
from urlscan import urlscan
import unittest


class TestUrlScanMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                urlscan.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once_with(2)

    def test_main_success(self):
        output = {"foo": "bar"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('urlscan.urlscan.analyze', new=MagicMock(return_value=output)) as mock:
                sys.argv = ["cmd", "input"]
                urlscan.main()
                expected = '{"foo": "bar"}\n'
                self.assertEqual(mock_stdout.getvalue(), expected)
                mock.assert_called_once()

    def test_checkConfigRequirements_notEnabled(self):
        conf = {"not_a_key": "abcd12345"}
        with self.assertRaises(SystemExit) as cm:
            urlscan.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_checkConfigRequirements_noApikey(self):
        conf = {"enabled": True, "not_a_key": "abcd12345"}
        with self.assertRaises(SystemExit) as cm:
            urlscan.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_checkConfigRequirements_Exist(self):
        conf = {"enabled": True, "api_key": "abcd12345"}
        config_exists = urlscan.checkConfigRequirements(conf)
        self.assertTrue(config_exists)

    def test_buildReq(self):
        conf = {'base_url': 'https://myurl/api/v1/', 'api_key': 'abcd12345', 'visibility': 'public'}
        artifact_type = "url"
        artifact_value = "https://abc.com"
        result = urlscan.buildReq(conf, artifact_type, artifact_value)
        self.assertEqual("https://myurl/api/v1/scan/", result[0])
        self.assertEqual({'API-Key': 'abcd12345'}, result[1])

    def test_sendReq(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            headers = {"API-Key": "abcd1234"}
            data = {"url": "https://urlscan.io", "visibility": "public"}
            response = urlscan.sendReq("https://myurl", headers=headers, data=data)
            mock.assert_called_once_with("POST", url="https://myurl", headers={"API-Key": "abcd1234"}, data={"url": "https://urlscan.io", "visibility": "public"})
            self.assertIsNotNone(response)

    def test_getReport_noRetry(self):
        output_report = MagicMock()
        type(output_report).status_code = PropertyMock(return_value=404)
        output_report_body = {"requests": "body"}
        output_report.json.return_value = output_report_body
        with patch('requests.request', new=MagicMock(return_value=output_report)) as mock:
            result = urlscan.getReport({'timeout': 0}, "https://abc.com/report")
            self.assertEqual(404, result.status_code)
            mock.assert_called_once()

    def test_getReport_withRetry(self):
        output_report = MagicMock()
        type(output_report).status_code = PropertyMock(return_value=404)
        output_report_body = {"requests": "body"}
        output_report.json.return_value = output_report_body
        with patch('requests.request', new=MagicMock(return_value=output_report)) as mock:
            result = urlscan.getReport({'timeout': 3}, "https://abc.com/report")
            self.assertEqual(404, result.status_code)
            mock.assert_has_calls([call('GET', 'https://abc.com/report'), call('GET', 'https://abc.com/report')])

    def test_prepareResults_sus(self):
        raw = {"requests": [{"request": {"requestId": "1"}}], "verdicts": {"overall": {"score": 50, "malicious": False, "hasVerdicts": False}}}
        results = urlscan.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "suspicious")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_mal(self):
        raw = {"requests": [{"request": {"requestId": "2"}}], "verdicts": {"overall": {"score": 100, "malicious": True, "hasVerdicts": False}}}
        results = urlscan.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "malicious")
        self.assertEqual(results["status"], "threat")

    def test_prepareResults_info(self):
        raw = {"requests": [{"request": {"requestId": "3"}}], "verdicts": {"overall": {"score": 0, "malicious": False, "hasVerdicts": False}}}
        results = urlscan.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "analysis_complete")
        self.assertEqual(results["status"], "info")

    def test_prepareResults_error(self):
        raw = {}
        results = urlscan.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_analyze(self):
        output_req = "https://myurl/report"
        output_report = MagicMock()
        output_report_body = {"requests": [{"request": {"requestId": "3"}}], "verdicts": {"overall": {"score": 0, "malicious": False, "hasVerdicts": False}}}
        output_report.json.return_value = output_report_body
        artifactInput = '{"value":"https://abc.com","artifactType":"url"}'
        conf = {'enabled': True, 'base_url': 'https://myurl/api/v1/', 'api_key': 'abcd12345', 'visibility': 'public'}
        with patch('urlscan.urlscan.sendReq', new=MagicMock(return_value=output_req)) as mock_req:
            with patch('urlscan.urlscan.getReport', new=MagicMock(return_value=output_report)) as mock_report:
                results = urlscan.analyze(conf, artifactInput)
                self.assertEqual(results["summary"], "analysis_complete")
                mock_req.assert_called_once()
                mock_report.assert_called_once()
