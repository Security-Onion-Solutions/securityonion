from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import threatfox
import unittest

class TestThreatfoxMethods(unittest.TestCase):

        #from Urlhaus_test
        def test_main_missing_input(self):
            print(1)
        def test_main_success(self):
            print(1)

        #result stores the output of the buildReq method
        #comparing result with expected output
        def test_buildReqHash(self):            
            result = threatfox.buildReq('hash', '2151c4b970eff0071948dbbc19066aa4')            
            self.assertEqual(result, {'query':'search_hash', 'hash':'2151c4b970eff0071948dbbc19066aa4'})
        def test_buildReqIP(self):
            result = threatfox.buildReq('ip','139.180.203.104:443')
            self.assertEqual(result, {'query':'search_ioc','search_term':'139.180.203.104:443'})
        def test_buildReqDomain(self):
            result = threatfox.buildReq('domain', 'https://google.com')
            self.assertEqual(result, {'query':'search_ioc', 'search_term':'https://google.com'})    
        def test_buildReqFalse(self):
            result = threatfox.buildReq('hash', '2151c4b970eff0071948dbbc19066aa4')   
            self.assertNotEqual(result, {})


        def test_sendReq(self):
            print(1)
        #not done
        # def test_prepareResults_none(self):
        #     #might need to change based on what they want
        #     raw = {}
        #     status = 'caution'
        #     summary = 'internal_failure'
        #     results = threatfox.prepareResults(raw)
        #     self.assertEqual(results['response'], raw)
        #     self.assertEqual(results['status'], status)
        #     self.assertEqual(results['summary'], summary)
            
            

        def test_prepareResults_invalidUrl(self):
            print(1)

        #not done need to add parameter in the sendReq
        # def test_prepareResults_threat(self):
        #     raw = {}
        #     status = 'threat'
        #     summary = 'Indicator that identifies a botnet command&control server (C&C)'
        #     query = threatfox.buildReq('hash','2151c4b970eff0071948dbbc19066aa4')     
        #     response = threatfox.sendReq('', query)
        #     results = threatfox.prepareResults(response)
        #     #self.assertEqual(results['response'], raw)
        #     self.assertEqual(results['status'], status)
        #     self.assertEqual(results['summary'], summary)
        #     print(1)

        def test_prepareResults_error(self):
            print(1)
        def test_analyze(self):
            print(1)