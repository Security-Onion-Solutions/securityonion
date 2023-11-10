from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import unittest
import elasticsearch
import helpers
import json

class TestElasticSearchMethods(unittest.TestCase):   

    #case for when no domain is provided
    def test_checkConfigRequirements(self):
        conf = {"domain":""}
        with self.assertRaises(SystemExit) as cm:
            elasticsearch.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_buildReqHash(self):
        numberOfResults = 1
        observableType = "hash"

        expectedQuery = {
            "from": 0,
            "size": numberOfResults,
            "query": {
                "wildcard": {
                    observableType: "*"
                }
            }
        }
        result = elasticsearch.buildReq(observableType,numberOfResults)    
        self.assertEqual(result, json.dumps(expectedQuery))

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
    
    

