from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import unittest
import elasticsearch
import helpers
import json

#python -m unittest .\elasticsearch_test.py

class TestElasticSearchMethods(unittest.TestCase):   

    '''Test that checks for empty and none values in configurables'''
    def test_checkConfigRequirements(self):
        conf = {"base_url":"", "authUser":"", "authPWD":"", "numResults":None,"api_key":"","index":"","timeDeltaMinutes": None,"timestampFieldName":"", "map":{}}
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
            response = elasticsearch.buildReq(
                observableType,numberOfResults)     
            self.assertEqual(json.dumps(response), json.dumps(expectedQuery))
            mock.assert_called_once()

    '''Test that checks sendReq method to expect a response from a requests.post'''
    def test_sendReq(self):
        conf = {"base_url":"test", "authUser":"test", "authPWD":"test", "api_key":"test","index":"test"}
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

       
        

       
    
    
    

