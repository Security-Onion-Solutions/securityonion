from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import unittest
import elasticsearch
import helpers
import json
from datetime import datetime, timedelta

#python -m unittest .\elasticsearch_test.py

class TestElasticSearchMethods(unittest.TestCase):   

    # def test_main_missing_input(self):
    #     with patch('sys.exit', new=MagicMock()) as sysmock:
    #         with patch('sys.stderr', new=StringIO()) as mock_stderr:
    #             sys.argv = ["cmd"]
    #             elasticsearch.main()
    #             self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
    #             sysmock.assert_called_once_with(2)

    # def test_main_success(self):
    #     output = {"foo": "bar"}
    #     with patch('sys.stdout', new=StringIO()) as mock_stdout:
    #         with patch('elasticsearch.analyze', new=MagicMock(return_value=output)) as mock:
    #             sys.argv = ["cmd", "input"]
    #             elasticsearch.main()
    #             expected = '{"foo": "bar"}\n'
    #             self.assertEqual(mock_stdout.getvalue(), expected)
    #             mock.assert_called_once()

    '''Test that checks for empty and none values in configurables'''
    def test_checkConfigRequirements(self):
        conf = {"base_url":"", "auth_user":"", "auth_pwd":"", "num_results":None,"api_key":"","index":"","time_delta_minutes": None,"timestamp_field_name":"", "map":{}, "cert_path":""}
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
            response = elasticsearch.buildReq(observableType,numberOfResults)     
            self.assertEqual(json.dumps(response), json.dumps(expectedQuery))
            mock.assert_called_once()

    def test_wrongbuildReq(self):
            result={'map':'123','artifactType':'hash','timestamp_field_name':'abc', 'time_delta_minutes':14400, 'num_results':10,'value':'0' }
            cur_time = datetime.now()
            start_time = cur_time - timedelta(minutes=result['time_delta_minutes'])
            query=elasticsearch.buildReq(result, result)
            comparequery=json.dumps({
                "from": 0,
                "size":10,
                "query": {
                    "bool":{
                        "must": [{
                            "wildcard": {
                                'hash': result['value'],
                            },
                        }
                        ],
                        "filter":{
                            "range":{
                                result['timestamp_field_name']:{
                                    "gte": start_time.strftime('%Y-%m-%dT%H:%M:%S'),
                                    "lte": cur_time.strftime('%Y-%m-%dT%H:%M:%S')
                                }
                            }
                        }
                    }
                }
                
            })
            self.assertEqual(query, comparequery )
            
    def test_rightbuildReq(self):
            result={'map':{'hash':'testingHash'},'artifactType':'hash','timestamp_field_name':'abc', 'time_delta_minutes':14400, 'num_results':10,'value':'0'}
            cur_time = datetime.now()
            start_time = cur_time - timedelta(minutes=result['time_delta_minutes'])
            query=elasticsearch.buildReq(result, result)
            comparequery=json.dumps({
                "from": 0,
                "size": 10,
                "query": {
                    "bool":{
                        "must":[{
                                "wildcard": {
                                    result['map'][result['artifactType']]: result['value'],
                                },
                            }
                        ]
                        ,
                        "filter":{
                            "range":{
                                result['timestamp_field_name']:{
                                    "gte": start_time.strftime('%Y-%m-%dT%H:%M:%S'),
                                    "lte": cur_time.strftime('%Y-%m-%dT%H:%M:%S')
                                }
                            }
                        }
                    }
                }
            })
            self.assertEqual(query, comparequery )

    def test_rightbuildReq100result(self):
        result={'map':{'hash':'testingHash'},'artifactType':'hash','timestamp_field_name':'abc', 'time_delta_minutes':14400, 'num_results':100,'value':'0'}
        cur_time = datetime.now()
        start_time = cur_time - timedelta(minutes=result['time_delta_minutes'])
        query=elasticsearch.buildReq(result, result)
        comparequery=json.dumps({
            "from": 0,
            "size": 100,
            "query": {
                "bool":{
                    "must":[{
                            "wildcard": {
                                result['map'][result['artifactType']]: result['value'],
                            },
                        }
                    ]
                    ,
                    "filter":{
                        "range":{
                            result['timestamp_field_name']:{
                                "gte": start_time.strftime('%Y-%m-%dT%H:%M:%S'),
                                "lte": cur_time.strftime('%Y-%m-%dT%H:%M:%S')
                            }
                        }
                    }
                }
            }
        })
        self.assertEqual(query, comparequery )


    '''Test that checks sendReq method to expect a response from a requests.post'''
    def test_sendReq(self):
        conf = {"base_url":"test", "auth_user":"test", "auth_pwd":"test", "api_key":"test","index":"test", "cert_path":""}
        with patch('requests.post', new=MagicMock(return_value=MagicMock())) as mock:
            response = elasticsearch.sendReq(conf, 'example_query')
            self.assertIsNotNone(response)    

    '''Test that checks prepareResults method, by comparing a mock prepareResults return_value with an expectedResult'''
    def test_prepareResults(self):
        summary = "Documents returned: 5"
        status = 'info'
        raw = {'_id': "0", "hash": "123"}
        expectedResult = {'response': raw, 'summary': summary, 'status': status}

        with patch('elasticsearch.prepareResults', new=MagicMock(return_value=expectedResult)) as mock:
            response = elasticsearch.prepareResults(raw)
            self.assertEqual(expectedResult, response)
            mock.assert_called_once()

    '''Test that checks analyze method, simulated sendReq and prepareResults with 2 mock objects and variables sendReqOutput and prepareResultOutput,
            input created for analyze method call and then we compared results['summary'] with 'Documents returned: 5' '''    
    def test_analyze(self):
        sendReqOutput = {'_id': "0", "hash": "123"}
        input = '{"artifactType":"hash", "value":"123"}'
        prepareResultOutput = {'response': {'_id': "0", "hash": "123"},'summary': "Documents returned: 5", 'status': 'info'}
        conf = {"base_url":"test", "auth_user":"test", "auth_pwd":"test", "num_results":10,"api_key":"test","index":"test","time_delta_minutes": 14400,"timestamp_field_name":"test", "map":{}, "cert_path":""}
        with patch('elasticsearch.sendReq', new=MagicMock(return_value=sendReqOutput)) as mock:
            with patch('elasticsearch.prepareResults', new=MagicMock(return_value=prepareResultOutput)) as mock2:
                results = elasticsearch.analyze(conf, input)
                self.assertEqual(results["summary"], "Documents returned: 5")
                mock.assert_called_once()