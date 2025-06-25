from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import unittest
import echotrail


class TestEchoTrailMethods(unittest.TestCase):
    def test_main_success(self):
        with patch('sys.stdout', new=StringIO()) as mock_cmd:
            with patch('echotrail.analyze', new=MagicMock(return_value={'test': 'val'})) as mock:
                sys.argv = ["test", "test"]
                echotrail.main()
                expected = '{"test": "val"}\n'
                self.assertEqual(mock_cmd.getvalue(), expected)
                mock.assert_called_once()

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                echotrail.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once()

    def test_checkConfigRequirements(self):
        conf = {'base_url': 'https://www.randurl.xyz/', 'api_key': ''}
        with self.assertRaises(SystemExit) as cm:
            echotrail.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_sendReq(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            response = echotrail.sendReq(conf={'base_url': 'https://www.randurl.xyz/', 'api_key': 'randkey'}, observ_value='example_data')
            self.assertIsNotNone(response)
            mock.assert_called_once()

    def test_prepareResults_noinput(self):
        raw = {}
        sim_results = {'response': raw,
                       'status': 'info', 'summary': 'inconclusive'}
        results = echotrail.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_none(self):
        raw = {'query_status': 'no_result'}
        sim_results = {'response': raw,
                       'status': 'info', 'summary': 'inconclusive'}
        results = echotrail.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_filenames(self):
        raw = {'filenames': [["abc.exe", "def.exe"], ["abc.exe", "def.exe"]]}
        sim_results = {'response': raw,
                       'status': 'info', 'summary': 'abc.exe'}
        results = echotrail.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_tags(self):
        raw = {'tags': [["tag1", "tag2"], ["tag1", "tag2"]]}
        sim_results = {'response': raw,
                       'status': 'info', 'summary': 'tag1'}
        results = echotrail.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_analyze(self):
        sendReqOutput = {'threat': 'no_result'}
        input = '{"artifactType":"hash", "value":"1234"}'
        prepareResultOutput = {'response': '',
                               'summary': 'inconclusive', 'status': 'info'}
        conf = {"api_key": "xyz"}

        with patch('echotrail.sendReq', new=MagicMock(return_value=sendReqOutput)) as mock:
            with patch('echotrail.prepareResults', new=MagicMock(return_value=prepareResultOutput)) as mock2:
                results = echotrail.analyze(conf, input)
                self.assertEqual(results["summary"], "inconclusive")
                mock2.assert_called_once()
                mock.assert_called_once()
