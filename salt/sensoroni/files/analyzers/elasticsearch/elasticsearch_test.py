from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import unittest
import elasticsearch
import helpers


class TestElasticSearchMethods(unittest.TestCase):   

    #case for when no domain is provided
    def test_checkConfigRequirements(self):
        conf = {"domain":""}
        with self.assertRaises(SystemExit) as cm:
            elasticsearch.checkConfigRequirements(conf)
        self.assertEqual(cm.exception.code, 126)

    
    

