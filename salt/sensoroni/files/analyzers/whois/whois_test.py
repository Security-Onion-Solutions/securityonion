from io import StringIO
from unittest.mock import patch
from whois import whois
import unittest

class TestWhoisMethods(unittest.TestCase):

    def test_main(self):
        with patch('sys.stdout', new = StringIO()) as mock_stdout:
            whois.main()
            expected = '{"result":{ "requestId": "something-generated-by-whois", "someother_field": "more data" }, "summary": "botsrv.btc-goblin.ru"}\n'
            self.assertEqual(mock_stdout.getvalue(), expected)
