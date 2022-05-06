from io import StringIO
import sys
from unittest.mock import patch, MagicMock
from urlhaus import urlhaus
import unittest


class TestUrlhausMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            sys.argv = ["cmd"]
            urlhaus.main()
            self.assertEqual(mock_stdout.getvalue(), "ERROR: Missing input JSON\n")

    def test_main_success(self):
        output = {"foo": "bar"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('urlhaus.urlhaus.analyze', new=MagicMock(return_value=output)) as mock:
                sys.argv = ["cmd", "input"]
                urlhaus.main()
                expected = '{"foo": "bar"}\n'
                self.assertEqual(mock_stdout.getvalue(), expected)
                mock.assert_called_once()

    def test_buildReq(self):
        result = urlhaus.buildReq("test")
        self.assertEqual("test", result["url"])

    def test_sendReq(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            meta = {"baseUrl": "myurl"}
            response = urlhaus.sendReq(meta, "mypayload")
            mock.assert_called_once_with("POST", "myurl", data="mypayload")
            self.assertIsNotNone(response)

    def test_prepareResults_none(self):
        raw = {"query_status": "no_results"}
        results = urlhaus.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "no_results")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_invalidUrl(self):
        raw = {"query_status": "invalid_url"}
        results = urlhaus.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "invalid_url")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_threat(self):
        raw = {"query_status": "invalid_url"}  # This is overrided in this scenario
        raw["threat"] = "bad_actor"
        results = urlhaus.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "bad_actor")
        self.assertEqual(results["status"], "threat")

    def test_prepareResults_error(self):
        raw = {}
        results = urlhaus.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_analyze(self):
        output = {"threat": "malware_download"}
        artifactInput = '{"value":"foo","artifactType":"url"}'
        with patch('urlhaus.urlhaus.sendReq', new=MagicMock(return_value=output)) as mock:
            results = urlhaus.analyze(artifactInput)
            self.assertEqual(results["summary"], "malware_download")
            mock.assert_called_once()
