from unittest.mock import patch, MagicMock
import helpers
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
            mock.assert_called_once_with("No supported type detected!")

    def test_loadMetadata(self):
        input = 'urlhaus/urlhaus.py'
        data = helpers.loadMetadata(input)
        self.assertEqual(data["name"], "Urlhaus")

    def test_parseArtifact(self):
        input = '{"value":"foo","artifactType":"bar"}'
        data = helpers.parseArtifact(input)
        self.assertEqual(data["artifactType"], "bar")
        self.assertEqual(data["value"], "foo")
