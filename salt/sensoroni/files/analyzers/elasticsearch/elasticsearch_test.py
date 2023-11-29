from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import unittest
import elasticsearch
import helpers
import json

class TestElasticSearchMethods(unittest.TestCase):   

    '''Test that checks for empty and none values in configurables'''
    def test_checkConfigRequirements(self):
        conf = {"base_url":"", "authUser":"", "authPWD":"", "numResults":None,"api_key":"","index":"","timeDeltaMinutes": None,"timestampFieldName":"", "map":{}}
        with self.assertRaises(SystemExit) as cm:
            elasticsearch.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)


    '''Test that checks buildReq method, by comparing a mock buildReq result with an expectedQuery'''
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
                        conf['timestampFieldName']: {
                            "gte": start_time.strftime('%Y-%m-%dT%H:%M:%S'),
                            "lte": cur_time.strftime('%Y-%m-%dT%H:%M:%S')
                        }
                    }
                }
            }
        }
    }
        
        return_value = "not done"

        with patch('requests.post', new=MagicMock(return_value=MagicMock())) as mock:
            response = elasticsearch.buildReq(
                observableType,numberOfResults)
        
         
        self.assertEqual(json.dumps(return_value), json.dumps(expectedQuery))

    def test_sendReq(self):
        with patch('requests.post', new=MagicMock(return_value=MagicMock())) as mock:
            response = elasticsearch.sendReq(
                'example_index', 'example_query')
            self.assertIsNotNone(response)

    def test_prepareResults(self):
        #need to ask Wes how he wants the prepare result output
        #not done
        summary = "There are 5 hits recorded."
        status = 'info'
        raw = {'_id': "0", "hash": "123"}
        with patch('requests.post', new=MagicMock(return_value=MagicMock())) as mock:
            response = elasticsearch.prepareResults(
                'example_index', 'example_query')


        results = elasticsearch.prepareResults(raw)
        self.assertEqual(1, 1)
    
    

