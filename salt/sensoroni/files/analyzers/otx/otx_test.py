from io import StringIO
import sys
from unittest.mock import patch, MagicMock
from otx import otx
import unittest


class TestOtxMethods(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                otx.main()
                self.assertEqual(mock_stderr.getvalue(), "usage: cmd [-h] [-c CONFIG_FILE] artifact\ncmd: error: the following arguments are required: artifact\n")
                sysmock.assert_called_once_with(2)

    def test_main_success(self):
        output = {"foo": "bar"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('otx.otx.analyze', new=MagicMock(return_value=output)) as mock:
                sys.argv = ["cmd", "input"]
                otx.main()
                expected = '{"foo": "bar"}\n'
                self.assertEqual(mock_stdout.getvalue(), expected)
                mock.assert_called_once()

    def test_checkConfigRequirements(self):
        conf = {"not_a_key": "abcd12345"}
        with self.assertRaises(SystemExit) as cm:
            otx.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    def test_buildReq_domain(self):
        conf = {'base_url': 'https://myurl/', 'api_key': 'abcd12345'}
        artifact_type = "domain"
        artifact_value = "abc.com"
        result = otx.buildReq(conf, artifact_type, artifact_value)
        self.assertEqual("https://myurl/indicators/domain/abc.com/general", result[0])
        self.assertEqual({'X-OTX-API-KEY': 'abcd12345'}, result[1])

    def test_buildReq_hash(self):
        conf = {'base_url': 'https://myurl/', 'api_key': 'abcd12345'}
        artifact_type = "hash"
        artifact_value = "abcd1234"
        result = otx.buildReq(conf, artifact_type, artifact_value)
        self.assertEqual("https://myurl/indicators/file/abcd1234/general", result[0])
        self.assertEqual({'X-OTX-API-KEY': 'abcd12345'}, result[1])

    def test_buildReq_ip(self):
        conf = {'base_url': 'https://myurl/', 'api_key': 'abcd12345'}
        artifact_type = "ip"
        artifact_value = "192.168.1.1"
        result = otx.buildReq(conf, artifact_type, artifact_value)
        self.assertEqual("https://myurl/indicators/IPv4/192.168.1.1/general", result[0])
        self.assertEqual({'X-OTX-API-KEY': 'abcd12345'}, result[1])

    def test_buildReq_url(self):
        conf = {'base_url': 'https://myurl/', 'api_key': 'abcd12345'}
        artifact_type = "url"
        artifact_value = "https://abc.com"
        result = otx.buildReq(conf, artifact_type, artifact_value)
        self.assertEqual("https://myurl/indicators/url/https://abc.com/general", result[0])
        self.assertEqual({'X-OTX-API-KEY': 'abcd12345'}, result[1])

    def test_sendReq(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            url = "https://myurl="
            response = otx.sendReq(url, headers={"x-apikey": "xyz"})
            mock.assert_called_once_with("GET", "https://myurl=", headers={"x-apikey": "xyz"})
            self.assertIsNotNone(response)

    def test_prepareResults_harmless(self):
        raw = {
                     "whois": "http://whois.domaintools.com/192.168.1.1",
                     "reputation": 0,
                     "indicator": "192.168.1.1",
                     "type": "IPv4",
                     "pulse_info": {
                         "count": 0,
                         "pulses": [],
                         "related": {
                             "alienvault": {
                                 "adversary": [],
                                 "malware_families": []
                             }
                         }
                     },
                     "false_positive": [],
                     "sections": [
                         "general"
                     ]
                 }
        results = otx.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "harmless")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_likely_harmless(self):
        raw = {
                     "whois": "http://whois.domaintools.com/192.168.1.1",
                     "reputation": 49,
                     "indicator": "192.168.1.1",
                     "type": "IPv4",
                     "pulse_info": {
                         "count": 0,
                         "pulses": [],
                         "related": {
                             "alienvault": {
                                 "adversary": [],
                                 "malware_families": []
                             }
                         }
                     },
                     "false_positive": [],
                     "sections": [
                         "general"
                     ]
                 }
        results = otx.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "likely_harmless")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_suspicious(self):
        raw = {
                     "whois": "http://whois.domaintools.com/192.168.1.1",
                     "reputation": 50,
                     "indicator": "192.168.1.1",
                     "type": "IPv4",
                     "pulse_info": {
                         "count": 0,
                         "pulses": [],
                         "related": {
                             "alienvault": {
                                 "adversary": [],
                                 "malware_families": []
                             }
                         }
                     },
                     "false_positive": [],
                     "sections": [
                         "general"
                     ]
                 }
        results = otx.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "suspicious")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_threat(self):
        raw = {
                     "whois": "http://whois.domaintools.com/192.168.1.1",
                     "reputation": 75,
                     "indicator": "192.168.1.1",
                     "type": "IPv4",
                     "pulse_info": {
                         "count": 0,
                         "pulses": [],
                         "related": {
                             "alienvault": {
                                 "adversary": [],
                                 "malware_families": []
                             }
                         }
                     },
                     "false_positive": [],
                     "sections": [
                         "general"
                     ]
                 }
        results = otx.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "malicious")
        self.assertEqual(results["status"], "threat")

    def test_prepareResults_undetermined(self):
        raw = {
                  "alexa": "",
                  "base_indicator": {},
                  "domain": "Unavailable",
                  "false_positive": [],
                  "hostname": "Unavailable",
                  "indicator": "http://192.168.1.1",
                  "pulse_info": {
                      "count": 0,
                      "pulses": [],
                      "references": [],
                      "related": {
                          "alienvault": {
                              "adversary": [],
                              "industries": [],
                              "malware_families": [],
                              "unique_indicators": 0
                          },
                          "other": {
                              "adversary": [],
                              "industries": [],
                              "malware_families": [],
                              "unique_indicators": 0
                          }
                      }
                  },
                  "sections": [
                      "general"
                  ],
                  "type": "url",
                  "type_title": "URL",
                  "validation": []
              }
        results = otx.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "analyzer_analysis_complete")
        self.assertEqual(results["status"], "info")

    def test_prepareResults_error(self):
        raw = {}
        results = otx.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_analyze(self):
        output = {
                     "whois": "http://whois.domaintools.com/192.168.1.1",
                     "reputation": 0,
                     "indicator": "192.168.1.1",
                     "type": "IPv4",
                     "pulse_info": {
                         "count": 0,
                         "pulses": [],
                         "related": {
                             "alienvault": {
                                 "adversary": [],
                                 "malware_families": []
                             }
                         }
                     },
                     "false_positive": [],
                     "sections": [
                         "general"
                     ]
                 }

        artifactInput = '{"value":"192.168.1.1","artifactType":"ip"}'
        conf = {"base_url": "https://myurl/", "api_key": "xyz"}
        with patch('otx.otx.sendReq', new=MagicMock(return_value=output)) as mock:
            results = otx.analyze(conf, artifactInput)
            self.assertEqual(results["summary"], "harmless")
            mock.assert_called_once()
