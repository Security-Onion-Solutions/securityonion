from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import threatfox
import unittest


class TestThreatfoxMethods(unittest.TestCase):
    # This should 1. create a fake cmd input with no args
    # and 2. hit the else statement in main. It then
    # compares the console output to a hardcoded string.

    # DOES NOT WORK WITH ARGPARSE/MAIN METHOD

    def test_main_missing_input(self):
        with patch('sys.stdout', new=StringIO()) as mock_cmd:
            sys.argv = ["cmd"]
            threatfox.main()
            self.assertEqual(mock_cmd.getvalue(),
                             'ERROR: Input is not in proper JSON format\n')

    # This should 1. create a fake cmd input with 1 arg
    # and 2. hit the if statement in main which runs a mock
    # analyze method with return value of {'test': 'val'}.
    # threatfox.main() should then print that to the console,
    # which is then asserted equal against an expected value.

    def test_main_success(self):
        with patch('sys.stdout', new=StringIO()) as mock_cmd:
            with patch('threatfox.analyze', new=MagicMock(return_value={'test': 'val'})) as mock:
                sys.argv = ["cmd", "input"]
                threatfox.main()
                expected = '{"test": "val"}\n'
                self.assertEqual(mock_cmd.getvalue(), expected)
                mock.assert_called_once()

    # result stores the output of the buildReq method
    # comparing result with expected output
    def test_buildReqHash(self):
        result = threatfox.buildReq('hash', '2151c4b970eff0071948dbbc19066aa4')
        self.assertEqual(
            result, {'query': 'search_hash', 'hash': '2151c4b970eff0071948dbbc19066aa4'})

    def test_buildReqIP(self):
        result = threatfox.buildReq('ip', '139.180.203.104:443')
        self.assertEqual(
            result, {'query': 'search_ioc', 'search_term': '139.180.203.104:443'})

    def test_buildReqDomain(self):
        result = threatfox.buildReq('domain', 'https://google.com')
        self.assertEqual(
            result, {'query': 'search_ioc', 'search_term': 'https://google.com'})

    def test_buildReqFalse(self):
        result = threatfox.buildReq('hash', '2151c4b970eff0071948dbbc19066aa4')
        self.assertNotEqual(result, {})

    # simulate API response and makes sure sendReq gives a response, we are just checking if sendReq gives back anything
    def test_sendReq(self):
        with patch('requests.post', new=MagicMock(return_value=MagicMock())) as mock:
            response = threatfox.sendReq(
                {'baseUrl': 'https://www.randurl.xyz'}, 'example_data')
            self.assertIsNotNone(response)
            mock.assert_called_once()

    # result stores the output of the prepareResults method, comparing result with expected output
    def test_prepareResults_noinput(self):
        # no/improper given input
        raw = {}
        sim_results = {'response': raw, 'status': 'caution',
                       'summary': 'internal_failure'}
        results = threatfox.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_none(self):
        # no results
        raw = {'query_status': 'no_result'}
        sim_results = {'response': raw,
                       'status': 'info', 'summary': 'no result'}
        results = threatfox.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_illegal_search_term(self):
        # illegal search term
        raw = {'query_status': 'illegal_search_term'}
        expected = {'response': raw, 'status': 'info', 'summary': 'no result'}
        results = threatfox.prepareResults(raw)
        self.assertEqual(results, expected)

    def test_prepareResults_threat(self):
        # threat exists
        raw = {'query_status': 'ok', 'data': [
            {'threat_type': 'threat', 'confidence_level': 94}]}
        sim_results = {'response': raw,
                       'summary': 'threat', 'status': 'threat'}
        results = threatfox.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_threat_type_does_not_exist(self):
        # threat type does not exist
        raw = {'query_status': 'ok', 'data': [
            {'threat_type': '', 'threat_type_desc': 'description', 'confidence_level': 0}]}
        sim_results = {'response': raw,
                       'summary': 'description', 'status': 'ok'}
        results = threatfox.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_threat_type_25_or_less(self):
        # confidence level of 25 or less
        raw = {'query_status': 'ok', 'data': [
            {'threat_type': 'threat', 'confidence_level': 25}]}
        sim_results = {'response': raw,
                       'summary': 'threat', 'status': 'ok'}
        results = threatfox.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_threat_type_greater_than_25(self):
        # confidence level greater than 25
        raw = {'query_status': 'ok', 'data': [
            {'threat_type': 'threat', 'confidence_level': 26}]}
        sim_results = {'response': raw,
                       'summary': 'threat', 'status': 'info'}
        results = threatfox.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_threat_type_greater_than_50(self):
        # confidence level greater than 50
        raw = {'query_status': 'ok', 'data': [
            {'threat_type': 'threat', 'confidence_level': 51}]}
        sim_results = {'response': raw,
                       'summary': 'threat', 'status': 'caution'}
        results = threatfox.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_threat_type_greater_than_75(self):
        # confidence level greater than 75
        raw = {'query_status': 'ok', 'data': [
            {'threat_type': 'threat', 'confidence_level': 76}]}
        sim_results = {'response': raw,
                       'summary': 'threat', 'status': 'threat'}
        results = threatfox.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_prepareResults_error(self):
        raw = {}
        sim_results = {'response': raw, 'status': 'caution',
                       'summary': 'internal_failure'}
        results = threatfox.prepareResults(raw)
        self.assertEqual(results, sim_results)

    def test_analyze(self):
        """simulated sendReq and prepareResults with 2 mock objects and variables sendReqOutput and prepareResultOutput,
            input created for analyze method call and then we compared results['summary'] with 'no result' """
        sendReqOutput = {'threat': 'no_result'}
        input = '{"artifactType":"hash", "value":"1234"}'
        prepareResultOutput = {'response': '',
                               'summary': 'no result', 'status': ''}
        with patch('threatfox.sendReq', new=MagicMock(return_value=sendReqOutput)) as mock:
            with patch('threatfox.prepareResults', new=MagicMock(return_value=prepareResultOutput)) as mock2:
                results = threatfox.analyze(input)
                self.assertEqual(results["summary"], "no result")
                mock.assert_called_once()
                mock2.assert_called_once()
