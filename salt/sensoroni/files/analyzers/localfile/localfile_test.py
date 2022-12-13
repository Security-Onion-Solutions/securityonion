from io import StringIO
import sys
from unittest.mock import patch, MagicMock
from localfile import localfile
import unittest


class TestLocalfileMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                localfile.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once_with(2)

    def test_main_success(self):
        output = {"foo": "bar"}
        conf = {"file_path": ["somefile.csv"]}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('localfile.localfile.analyze', new=MagicMock(return_value=output)) as mock:
                with patch('helpers.loadConfig', new=MagicMock(return_value=conf)) as lcmock:
                    sys.argv = ["cmd", "input"]
                    localfile.main()
                    expected = '{"foo": "bar"}\n'
                    self.assertEqual(mock_stdout.getvalue(), expected)
                    mock.assert_called_once()
                    lcmock.assert_called_once()

    def test_searchFile_multiple_found(self):
        artifact = "abcd1234"
        results = localfile.searchFile(artifact, ["localfile_test.csv"])
        self.assertEqual(results[0]["indicator"], "abcd1234")
        self.assertEqual(results[0]["description"], "This is a test!")
        self.assertEqual(results[0]["reference"], "Testing")
        self.assertEqual(results[1]["indicator"], "abcd1234")
        self.assertEqual(results[1]["description"], "This is another test!")

    def test_searchFile_single_found(self):
        artifact = "192.168.1.1"
        results = localfile.searchFile(artifact, ["localfile_test.csv"])
        self.assertEqual(results["indicator"], "192.168.1.1")
        self.assertEqual(results["description"], "Yet another test!")
        self.assertEqual(results["reference"], "Testing")

    def test_searchFile_not_found(self):
        artifact = "youcan'tfindme"
        results = localfile.searchFile(artifact, ["localfile_test.csv"])
        self.assertEqual(results, "No results")

    def test_prepareResults_none(self):
        raw = "No results"
        results = localfile.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "no_results")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_ok(self):
        raw = [
                {
                    "description": "This is one BAD piece of malware!",
                    "filename": "/opt/sensoroni/analyzers/localfile/intel.csv",
                    "indicator": "abc1234",
                    "reference": "https://myintelservice"
                },
                {
                    "filename": "/opt/sensoroni/analyzers/localfile/random.csv",
                    "randomcol1": "myothervalue",
                    "randomcol2": "myotherothervalue",
                    "value": "abc1234"
                }
              ]
        results = localfile.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "suspicious")
        self.assertEqual(results["status"], "info")

    def test_prepareResults_error(self):
        raw = {}
        results = localfile.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_analyze(self):
        output = [
                   {
                       "description": "This is one BAD piece of malware!",
                       "filename": "/opt/sensoroni/analyzers/localfile/intel.csv",
                       "indicator": "abc1234",
                       "reference": "https://myintelservice"
                   },
                   {
                       "filename": "/opt/sensoroni/analyzers/localfile/random.csv",
                       "randomcol1": "myothervalue",
                       "randomcol2": "myotherothervalue",
                       "value": "abc1234"
                   }
                 ]
        artifactInput = '{"value":"foo","artifactType":"url"}'
        conf = {"file_path": ['/home/intel.csv']}
        with patch('localfile.localfile.searchFile', new=MagicMock(return_value=output)) as mock:
            results = localfile.analyze(conf, artifactInput)
            self.assertEqual(results["summary"], "suspicious")
            mock.assert_called_once()
