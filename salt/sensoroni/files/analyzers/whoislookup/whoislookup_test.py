from io import StringIO
import sys
from unittest.mock import patch, MagicMock
from whoislookup import whoislookup
import unittest
import whoisit


class TestWhoisLookupMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                whoislookup.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once_with(2)

    def test_main_success(self):
        output = {"foo": "bar"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('whoislookup.whoislookup.analyze', new=MagicMock(return_value=output)) as mock:
                sys.argv = ["cmd", "input"]
                whoislookup.main()
                expected = '{"foo": "bar"}\n'
                self.assertEqual(mock_stdout.getvalue(), expected)
                mock.assert_called_once()

    def test_sendReq(self):
        output = {"foo": "bar"}
        with patch('whoisit.domain', new=MagicMock(return_value=output)) as mock:
            response = whoislookup.sendReq("abcd1234.com")
            mock.assert_called_once_with("abcd1234.com", raw=True)
            self.assertIsNotNone(response)
            self.assertEqual(response, output)

    def test_sendReqNotFound(self):
        mock = MagicMock()
        mock.side_effect = whoisit.errors.ResourceDoesNotExist()
        with patch('whoisit.domain', new=mock):
            response = whoislookup.sendReq("abcd1234.com")
            mock.assert_called_once_with("abcd1234.com", raw=True)
            self.assertIsNotNone(response)
            self.assertEqual(response, "Not found.")

    def test_sendReqQueryError(self):
        mock = MagicMock()
        mock.side_effect = whoisit.errors.QueryError("error")
        with patch('whoisit.domain', new=mock):
            response = whoislookup.sendReq("abcd1234.com")
            mock.assert_called_once_with("abcd1234.com", raw=True)
            self.assertIsNotNone(response)
            self.assertEqual(response, "QueryError: error")

    def test_prepareResults_none(self):
        raw = "Not found."
        results = whoislookup.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "no_results")
        self.assertEqual(results["status"], "info")

    def test_prepareResults_info(self):
        raw = {"hash": "14af04b8e69682782607a0c5796ca56999eda6b3", "last_seen": "123456", "av_detection_percentage": 0}
        results = whoislookup.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "analysis_complete")
        self.assertEqual(results["status"], "info")

    def test_prepareResults_query_error(self):
        raw = "QueryError: blahblahblah"
        results = whoislookup.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "invalid_input")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_error(self):
        raw = {}
        results = whoislookup.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_analyze(self):
        output = {"hash": "14af04b8e69682782607a0c5796ca56999eda6b3", "last_seen": "NO_DATA", "av_detection_percentage": 0}
        artifactInput = '{"value": "14af04b8e69682782607a0c5796ca56999eda6b3", "artifactType": "domain"}'
        with patch('whoislookup.whoislookup.sendReq', new=MagicMock(return_value=output)) as mock:
            results = whoislookup.analyze(artifactInput)
            self.assertEqual(results["summary"], "analysis_complete")
            mock.assert_called_once()
