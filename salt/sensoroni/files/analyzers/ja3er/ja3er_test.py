from io import StringIO
import sys
from unittest.mock import patch, MagicMock
from ja3er import ja3er
import unittest


class TestJa3erMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                ja3er.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once_with(2)

    def test_main_success(self):
        output = {"foo": "bar"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('ja3er.ja3er.analyze', new=MagicMock(return_value=output)) as mock:
                sys.argv = ["cmd", "input"]
                ja3er.main()
                expected = '{"foo": "bar"}\n'
                self.assertEqual(mock_stdout.getvalue(), expected)
                mock.assert_called_once()

    def test_sendReq(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            meta = {}
            conf = {"base_url": "myurl/"}
            hash = "abcd1234"
            response = ja3er.sendReq(conf=conf, meta=meta, hash=hash)
            mock.assert_called_once_with("GET", "myurl/abcd1234")
            self.assertIsNotNone(response)

    def test_prepareResults_none(self):
        raw = {"error": "Sorry no values found"}
        results = ja3er.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "no_results")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_invalidHash(self):
        raw = {"error": "Invalid hash"}
        results = ja3er.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "invalid_input")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_internal_failure(self):
        raw = {"error": "unknown"}
        results = ja3er.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_info(self):
        raw = [{"User-Agent": "Blah/5.0", "Count": 24874, "Last_seen": "2022-04-08 16:18:38"}, {"Comment": "Brave browser v1.36.122\n\n", "Reported": "2022-03-28 20:26:42"}]
        results = ja3er.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "suspicious")
        self.assertEqual(results["status"], "info")

    def test_analyze(self):
        output = {"info": "Results found."}
        artifactInput = '{"value":"abcd1234","artifactType":"ja3"}'
        conf = {"base_url": "myurl/"}
        with patch('ja3er.ja3er.sendReq', new=MagicMock(return_value=output)) as mock:
            results = ja3er.analyze(conf, artifactInput)
            self.assertEqual(results["summary"], "suspicious")
            mock.assert_called_once()
