from unittest.mock import patch, MagicMock
import helpers
import os
import unittest


class TestHelpersMethods(unittest.TestCase):

    def test_checkSupportedType(self):
        with patch('sys.exit', new=MagicMock()) as mock:
            meta = {"supportedTypes": ["ip", "foo"]}
            result = helpers.checkSupportedType(meta, "ip")
            self.assertTrue(result)
            mock.assert_not_called()

            result = helpers.checkSupportedType(meta, "bar")
            self.assertFalse(result)
            mock.assert_called_once_with(126)

    def test_loadMetadata(self):
        dir = os.path.dirname(os.path.realpath(__file__))
        input = dir + '/urlhaus/urlhaus.py'
        data = helpers.loadMetadata(input)
        self.assertEqual(data["name"], "Urlhaus")

    def test_loadConfig(self):
        dir = os.path.dirname(os.path.realpath(__file__))
        data = helpers.loadConfig(dir + "/virustotal/virustotal.yaml")
        self.assertEqual(data["base_url"], "https://www.virustotal.com/api/v3/search?query=")

    def test_parseArtifact(self):
        input = '{"value":"foo","artifactType":"bar"}'
        data = helpers.parseArtifact(input)
        self.assertEqual(data["artifactType"], "bar")
        self.assertEqual(data["value"], "foo")

    def test_verifyNonEmptyListValue(self):
        conf = {"file_path": ['testfile.csv']}
        path = 'file_path'
        self.assertTrue(conf, path)

    def test_verifyNonEmptyListValueIsEmpty(self):
        conf = {"file_path": ""}
        with self.assertRaises(SystemExit) as cm:
            helpers.verifyNonEmptyListValue(conf, 'file_path')
            self.assertEqual(cm.exception.code, 126)
