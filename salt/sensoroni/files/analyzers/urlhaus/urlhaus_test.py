from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import unittest
from urlhaus import urlhaus


class TestUrlhausMethods(unittest.TestCase):

    def test_main_success(self):
        output = {"foo": "bar"}
        config = {"api_key": "test_key"}
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            with patch('urlhaus.urlhaus.analyze', new=MagicMock(return_value=output)) as mock_analyze:
                with patch('helpers.loadConfig', new=MagicMock(return_value=config)) as mock_config:
                    sys.argv = ["cmd", "input"]
                    urlhaus.main()
                    expected = '{"foo": "bar"}\n'
                    self.assertEqual(mock_stdout.getvalue(), expected)
                    mock_analyze.assert_called_once()
                    mock_config.assert_called_once()

    def test_buildReq(self):
        result = urlhaus.buildReq("test")
        self.assertEqual("test", result["url"])

    def test_sendReq(self):
        with patch('requests.request', new=MagicMock(return_value=MagicMock())) as mock:
            conf = {"api_key": "test_key"}
            meta = {"baseUrl": "myurl"}
            response = urlhaus.sendReq(conf, meta, "mypayload")
            mock.assert_called_once_with("POST", "myurl", data="mypayload", headers={"Auth-Key": "test_key"})
            self.assertIsNotNone(response)

    def test_prepareResults_none(self):
        raw = {"query_status": "no_results"}
        results = urlhaus.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "no_results")
        self.assertEqual(results["status"], "ok")

    def test_prepareResults_invalidUrl(self):
        raw = {"query_status": "invalid_url"}
        results = urlhaus.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "invalid_url")
        self.assertEqual(results["status"], "caution")

    def test_prepareResults_threat(self):
        raw = {"query_status": "invalid_url"}  # This is overrided in this scenario
        raw["threat"] = "bad_actor"
        results = urlhaus.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "bad_actor")
        self.assertEqual(results["status"], "threat")

    def test_prepareResults_error(self):
        raw = {}
        results = urlhaus.prepareResults(raw)
        self.assertEqual(results["response"], raw)
        self.assertEqual(results["summary"], "internal_failure")
        self.assertEqual(results["status"], "caution")

    def test_analyze(self):
        output = {"threat": "malware_download"}
        config = {"api_key": "test_key"}
        artifactInput = '{"value":"foo","artifactType":"url"}'
        with patch('urlhaus.urlhaus.sendReq', new=MagicMock(return_value=output)) as mock:
            results = urlhaus.analyze(config, artifactInput)
            self.assertEqual(results["summary"], "malware_download")
            mock.assert_called_once()

    def test_checkConfigRequirements_valid(self):
        config = {"api_key": "test_key"}
        self.assertTrue(urlhaus.checkConfigRequirements(config))

    def test_checkConfigRequirements_missing_key(self):
        config = {}
        with self.assertRaises(SystemExit) as cm:
            urlhaus.checkConfigRequirements(config)
        self.assertEqual(cm.exception.code, 126)
