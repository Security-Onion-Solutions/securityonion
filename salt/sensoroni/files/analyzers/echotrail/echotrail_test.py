from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import unittest
import echotrail
import helpers

class TestEchoTrailMethods(unittest.TestCase):

    def test_main_success(self):
        with patch('sys.stdout', new=StringIO()) as mock_cmd:
            with patch('echotrail.analyze', new=MagicMock(return_value={'test': 'val'})) as mock:
                sys.argv = ["echotrail", '{"artifactType": "hash", "value": "1234"}']
                echotrail.main()
                expected = '{"test": "val"}\n'
                self.assertEqual(mock_cmd.getvalue(), expected)
                mock.assert_called_once()

    def test_sendReq(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            response = echotrail.sendReq(
                {'base_url': 'https://www.randurl.xyz/'}, 'example_data')
            self.assertIsNotNone(response)
 
    def test_prepareResults_noinput(self):
        raw = {}
        sim_results = {'response': raw, 'status': 'info', 'summary': 'inconclusive'}
        results = echotrail.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_none(self):
        raw = {'query_status': 'no_result'}
        sim_results = {'response': raw, 'status': 'info', 'summary': 'inconclusive'}
        results = echotrail.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_analyze(self):
        sendReqOutput = {'threat': 'no_result'}
        input = '{"artifactType":"hash", "value":"1234"}'
        prepareResultOutput = {'response': '', 'summary': 'inconclusive', 'status': 'info'}

        with patch('echotrail.sendReq', new=MagicMock(return_value=sendReqOutput)) as mock:
            with patch('echotrail.prepareResults', new=MagicMock(return_value=prepareResultOutput)) as mock2:
                results = echotrail.analyze(helpers.loadConfig, input)
                self.assertEqual(results["summary"], "inconclusive")


