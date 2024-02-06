# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

from io import StringIO
import sys
from unittest.mock import patch, MagicMock
import unittest
import importlib
soyaml = importlib.import_module("so-yaml")


class TestRemove(unittest.TestCase):

    def test_main_missing_input(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stdout:
                sys.argv = ["cmd"]
                soyaml.main()
                sysmock.assert_called_once_with(1)
                self.assertIn(mock_stdout.getvalue(), "Usage:")

    def test_main_help_locked(self):
        filename = "/tmp/so-yaml.lock"
        file = open(filename, "w")
        file.write = "fake lock file"
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stdout:
                with patch('time.sleep', new=MagicMock()) as mock_sleep:
                    sys.argv = ["cmd", "help"]
                    soyaml.main()
                    sysmock.assert_called()
                    mock_sleep.assert_called_with(2)
                    self.assertIn(mock_stdout.getvalue(), "Usage:")

    def test_main_help(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stdout:
                sys.argv = ["cmd", "help"]
                soyaml.main()
                sysmock.assert_called()
                self.assertIn(mock_stdout.getvalue(), "Usage:")

    def test_remove(self):
        filename = "/tmp/so-yaml_test-remove.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: abc }, key2: false}")
        file.close()

        soyaml.remove([filename, "key1"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key2: false\n"
        self.assertEqual(actual, expected)

    def test_remove_nested(self):
        filename = "/tmp/so-yaml_test-remove.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: abc }, key2: false}")
        file.close()

        soyaml.remove([filename, "key1.child2"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\nkey2: false\n"
        self.assertEqual(actual, expected)

    def test_remove_nested_deep(self):
        filename = "/tmp/so-yaml_test-remove.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: ab } }, key2: false}")
        file.close()

        soyaml.remove([filename, "key1.child2.deep1"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2:\n    deep2: ab\nkey2: false\n"
        self.assertEqual(actual, expected)

    def test_remove_missing_args(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stdout:
                filename = "/tmp/so-yaml_test-remove.yaml"
                file = open(filename, "w")
                file.write("{key1: { child1: 123, child2: abc }, key2: false}")
                file.close()

                soyaml.remove([filename])

                file = open(filename, "r")
                actual = file.read()
                file.close()

                expected = "{key1: { child1: 123, child2: abc }, key2: false}"
                self.assertEqual(actual, expected)
                sysmock.assert_called_once_with(1)
                self.assertIn(mock_stdout.getvalue(), "Missing filename or key arg\n")

    def test_append(self):
        filename = "/tmp/so-yaml_test-remove.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: abc }, key2: false, key3: [a,b,c]}")
        file.close()

        soyaml.append([filename, "key3", "d"])

        file = open(filename, "r")
        actual = file.read()
        file.close()
        expected = "key1:\n  child1: 123\n  child2: abc\nkey2: false\nkey3:\n- a\n- b\n- c\n- d\n"
        self.assertEqual(actual, expected)

    def test_append_nested(self):
        filename = "/tmp/so-yaml_test-remove.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: [a,b,c] }, key2: false, key3: [e,f,g]}")
        file.close()

        soyaml.append([filename, "key1.child2", "d"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2:\n  - a\n  - b\n  - c\n  - d\nkey2: false\nkey3:\n- e\n- f\n- g\n"
        self.assertEqual(actual, expected)

    def test_append_nested_deep(self):
        filename = "/tmp/so-yaml_test-remove.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        soyaml.append([filename, "key1.child2.deep2", "d"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2:\n    deep1: 45\n    deep2:\n    - a\n    - b\n    - c\n    - d\nkey2: false\nkey3:\n- e\n- f\n- g\n"
        self.assertEqual(actual, expected)

    def test_append_key_noexist(self):
        filename = "/tmp/so-yaml_test-append.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                sys.argv = ["cmd", "append", filename, "key4", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual(mock_stdout.getvalue(), "The key provided does not exist. No action was taken on the file.\n")

    def test_append_key_noexist_deep(self):
        filename = "/tmp/so-yaml_test-append.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                sys.argv = ["cmd", "append", filename, "key1.child2.deep3", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual(mock_stdout.getvalue(), "The key provided does not exist. No action was taken on the file.\n")

    def test_append_key_nonlist(self):
        filename = "/tmp/so-yaml_test-append.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                sys.argv = ["cmd", "append", filename, "key1", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual(mock_stdout.getvalue(), "The existing value for the given key is not a list. No action was taken on the file.\n")

    def test_append_key_nonlist_deep(self):
        filename = "/tmp/so-yaml_test-append.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stdout', new=StringIO()) as mock_stdout:
                sys.argv = ["cmd", "append", filename, "key1.child2.deep1", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual(mock_stdout.getvalue(), "The existing value for the given key is not a list. No action was taken on the file.\n")
