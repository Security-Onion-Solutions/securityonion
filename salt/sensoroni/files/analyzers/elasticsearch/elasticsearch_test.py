from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import unittest
import elasticsearch
import json
from datetime import datetime, timedelta


class TestElasticSearchMethods(unittest.TestCase):

    '''Test that the analyzer main method work as expect when not given enough input'''
    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                elasticsearch.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once_with(2)

    '''Test that analyzer main method work as expect when all required input is given'''
    def test_main_success(self):
        conf = {"base_url": "test", "auth_user": "test", "auth_pwd": "test", "api_key": "test", "index": "test", "time_delta_minutes": 14400, "map": {}, "cert_path": ""}
        with patch('elasticsearch.helpers.loadConfig', new=MagicMock(return_value=conf))as mock_yaml:
            with patch('sys.stdout', new=StringIO()) as mock_cmd:
                with patch('elasticsearch.analyze', new=MagicMock(return_value={'foo': 'bar'})) as mock:
                    sys.argv = ["cmd", "conf"]
                    elasticsearch.main()
                    expected = '{"foo": "bar"}\n'
                    self.assertEqual(mock_cmd.getvalue(), expected)
                    mock.assert_called_once()
                    mock_yaml.assert_called_once()

    '''Test that checks for empty and none values in configurables'''
    def test_checkConfigRequirements_no_num_results(self):
        conf = {"base_url": "https://baseurl", "auth_user": "test",
                "auth_pwd": "test", "num_results": None, "api_key": "abcd1234",
                "index": "_all", "time_delta_minutes": 12345, "timestamp_field_name": "@timestamp",
                "map": {"test": "test"}, "cert_path": "/cert"}
        with self.assertRaises(SystemExit) as cm:
            elasticsearch.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_checkConfigRequirements_no_delta(self):
        conf = {"base_url": "https://baseurl", "auth_user": "test",
                "auth_pwd": "test", "num_results": 1, "api_key": "abcd1234",
                "index": "_all", "time_delta_minutes": None, "timestamp_field_name": "@timestamp",
                "map": {"test": "test"}, "cert_path": "/cert"}
        with self.assertRaises(SystemExit) as cm:
            elasticsearch.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_checkConfigRequirements_no_auth_user(self):
        conf = {"base_url": "https://baseurl", "auth_user": None, "auth_pwd": "test",
                "num_results": "1", "api_key": None, "index": "_all", "time_delta_minutes": 12345,
                "timestamp_field_name": "@timestamp", "map": {"test": "test"}, "cert_path": "/cert"}
        with self.assertRaises(SystemExit) as cm:
            elasticsearch.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    '''Test that checks buildReq method, by comparing a mock buildReq result with an expectedQuery, used a mock object to simulate an expectedQuery
        since Elasticsearch buildReq uses values in the config'''

    def test_checkConfigRequirements_no_index(self):
        conf = {"base_url": "https://baseurl", "auth_user": "test", "auth_pwd": "test",
                "num_results": "1", "api_key": "abcd1234", "index": None, "time_delta_minutes": 12345,
                "timestamp_field_name": "@timestamp", "map": {"test": "test"}, "cert_path": "/cert"}
        with self.assertRaises(SystemExit) as cm:
            elasticsearch.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_checkConfigRequirements_no_base_url(self):
        conf = {"base_url": None, "auth_user": "test", "auth_pwd": "test", "num_results": "1",
                "api_key": "abcd1234", "index": "_all", "time_delta_minutes": 12345,
                "timestamp_field_name": "@timestamp", "map": {"test": "test"}, "cert_path": "/cert"}
        with self.assertRaises(SystemExit) as cm:
            elasticsearch.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_checkConfigRequirements_no_timestamp_field_name(self):
        conf = {"base_url": "https://baseurl", "auth_user": "test", "auth_pwd": "test", "num_results": "1",
                "api_key": "abcd1234", "index": "_all", "time_delta_minutes": 12345,
                "timestamp_field_name": None, "map": {"test": "test"}, "cert_path": "/cert"}
        with self.assertRaises(SystemExit) as cm:
            elasticsearch.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_checkConfigRequirements_no_cert_path(self):
        conf = {"base_url": "https://baseurl", "auth_user": "test", "auth_pwd": "test", "num_results": "1",
                "api_key": "abcd1234", "index": "_all", "time_delta_minutes": 12345, "timestamp_field_name": "@timestamp",
                "map": {"test": "test"}, "cert_path": None}
        with self.assertRaises(SystemExit) as cm:
            elasticsearch.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    '''Test that checks buildReq method, by comparing a mock buildReq result with an expectedQuery, used a mock object to simulate an expectedQuery
        since Elasticsearch buildReq uses values in the config'''

    def test_buildReq(self):
        numberOfResults = 1
        observableType = "hash"
        expectedQuery = {
            "from": 0,
            "size": numberOfResults,
            "query": {
                "bool": {
                    "must": [{
                        "wildcard": {
                            observableType: observableType,
                        },
                    }
                    ],
                    "filter": {
                        "range": {
                            "@timestamp": {
                                "gte": ('2023-11-29T14:23:45'),
                                "lte": ('2023-11-29T14:23:45')
                            }
                        }
                    }
                }
            }
        }
        with patch('elasticsearch.buildReq', new=MagicMock(return_value=expectedQuery)) as mock:
            response = elasticsearch.buildReq(observableType, numberOfResults)
            self.assertEqual(json.dumps(response), json.dumps(expectedQuery))
            mock.assert_called_once()

    def test_wrongbuildReq(self):
        mapping = None
        result = {'map': mapping, 'artifactType': 'hash', 'timestamp_field_name': 'abc', 'time_delta_minutes': 14400, 'num_results': 10, 'value': '0'}
        cur_time = datetime.now()
        start_time = cur_time - timedelta(minutes=result['time_delta_minutes'])
        query = elasticsearch.buildReq(result, result)
        comparequery = json.dumps({
            "from": 0,
            "size": 10,
            "query": {
                "bool": {
                    "must": [{
                        "wildcard": {
                            'hash': result['value'],
                        },
                    }
                    ],
                    "filter": {
                        "range": {
                            result['timestamp_field_name']: {
                                "gte": start_time.strftime('%Y-%m-%dT%H:%M:%S'),
                                "lte": cur_time.strftime('%Y-%m-%dT%H:%M:%S')
                            }
                        }
                    }
                }
            }
        })
        self.assertEqual(query, comparequery)

    def test_rightbuildReq(self):
        result = {'map': {'hash': 'testingHash'}, 'artifactType': 'hash', 'timestamp_field_name': 'abc', 'time_delta_minutes': 14400, 'num_results': 10, 'value': '0'}
        cur_time = datetime.now()
        start_time = cur_time - timedelta(minutes=result['time_delta_minutes'])
        query = elasticsearch.buildReq(result, result)
        comparequery = json.dumps({
            "from": 0,
            "size": 10,
            "query": {
                "bool": {
                    "must": [{
                            "wildcard": {
                                result['map'][result['artifactType']]: result['value'],
                            },
                    }],
                    "filter": {
                        "range": {
                            result['timestamp_field_name']: {
                                "gte": start_time.strftime('%Y-%m-%dT%H:%M:%S'),
                                "lte": cur_time.strftime('%Y-%m-%dT%H:%M:%S')
                            }
                        }
                    }
                }
            }
        })
        self.assertEqual(query, comparequery)

    def test_rightbuildReq100result(self):
        result = {'map': {'hash': 'testingHash'}, 'artifactType': 'hash', 'timestamp_field_name': 'abc', 'time_delta_minutes': 14400, 'num_results': 100, 'value': '0'}
        cur_time = datetime.now()
        start_time = cur_time - timedelta(minutes=result['time_delta_minutes'])
        query = elasticsearch.buildReq(result, result)
        comparequery = json.dumps({
            "from": 0,
            "size": 100,
            "query": {
                "bool": {
                    "must": [{
                            "wildcard": {
                                result['map'][result['artifactType']]: result['value'],
                            },
                    }],
                    "filter": {
                        "range": {
                            result['timestamp_field_name']: {
                                "gte": start_time.strftime('%Y-%m-%dT%H:%M:%S'),
                                "lte": cur_time.strftime('%Y-%m-%dT%H:%M:%S')
                            }
                        }
                    }
                }
            }
        })
        self.assertEqual(query, comparequery)

    '''Test that checks sendReq method to expect a response from a requests.post'''
    def test_sendReq_user_password(self):
        conf = {"base_url": "test", "auth_user": "test", "auth_pwd": "test", "api_key": "test", "index": "test", "cert_path": ""}
        with patch('requests.post', new=MagicMock(return_value=MagicMock())) as mock:
            response = elasticsearch.sendReq(conf, 'example_query')
            self.assertIsNotNone(response)
            mock.assert_called_once

    def test_sendReq_apikey(self):
        conf = {"base_url": "test", "auth_user": None, "auth_pwd": None, "api_key": "abcd1234", "index": "test", "cert_path": ""}
        with patch('requests.post', new=MagicMock(return_value=MagicMock())) as mock:
            response = elasticsearch.sendReq(conf, 'example_query')
            self.assertIsNotNone(response)
            mock.assert_called_once

    '''Test that checks prepareResults method, by comparing a mock prepareResults return_value with an expectedResult'''
    def test_prepareResults(self):
        raw = {"hits": {"hits": [{"_id": 0, "hash": "123"}]}}
        results = elasticsearch.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "Documents returned: 1")
        self.assertEqual(results["status"], "info")

    '''Test that checks analyze method, simulated sendReq and prepareResults with 2 mock objects and variables sendReqOutput and prepareResultOutput,
            input created for analyze method call and then we compared results['summary'] with 'Documents returned: 5' '''
    def test_analyze(self):
        sendReqOutput = {'_id': "0", "hash": "123"}
        input = '{"artifactType": "hash", "value": "123"}'
        prepareResultOutput = {'response': {'_id': "0", "hash": "123"}, 'summary': "Documents returned: 5", 'status': 'info'}
        conf = {"base_url": "test", "auth_user": "test", "auth_pwd": "test", "num_results": 10, "api_key": "test", "index": "test",
                "time_delta_minutes": 14400, "timestamp_field_name": "test", "map": {}, "cert_path": "test"}
        with patch('elasticsearch.sendReq', new=MagicMock(return_value=sendReqOutput)) as mock:
            with patch('elasticsearch.prepareResults', new=MagicMock(return_value=prepareResultOutput)) as mock2:
                results = elasticsearch.analyze(conf, input)
                self.assertEqual(results["summary"], "Documents returned: 5")
                mock.assert_called_once()
                mock2.assert_called_once()
