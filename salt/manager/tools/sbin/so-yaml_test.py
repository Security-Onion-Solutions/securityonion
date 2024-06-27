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
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd"]
                soyaml.main()
                sysmock.assert_called_once_with(1)
                self.assertIn("Usage:", mock_stderr.getvalue())

    def test_main_help_locked(self):
        filename = "/tmp/so-yaml.lock"
        file = open(filename, "w")
        file.write = "fake lock file"
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                with patch('time.sleep', new=MagicMock()) as mock_sleep:
                    sys.argv = ["cmd", "help"]
                    soyaml.main()
                    sysmock.assert_called()
                    mock_sleep.assert_called_with(2)
                    self.assertIn("Usage:", mock_stderr.getvalue())

    def test_main_help(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "help"]
                soyaml.main()
                sysmock.assert_called()
                self.assertIn("Usage:", mock_stderr.getvalue())

    def test_remove_missing_arg(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "help"]
                soyaml.remove(["file"])
                sysmock.assert_called()
                self.assertIn("Missing filename or key arg\n", mock_stderr.getvalue())

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
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
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
                self.assertIn("Missing filename or key arg\n", mock_stderr.getvalue())

    def test_append_missing_arg(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "help"]
                soyaml.append(["file", "key"])
                sysmock.assert_called()
                self.assertIn("Missing filename, key arg, or list item to append\n", mock_stderr.getvalue())

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
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "append", filename, "key4", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The key provided does not exist. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_append_key_noexist_deep(self):
        filename = "/tmp/so-yaml_test-append.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "append", filename, "key1.child2.deep3", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The key provided does not exist. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_append_key_nonlist(self):
        filename = "/tmp/so-yaml_test-append.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "append", filename, "key1", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The existing value for the given key is not a list. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_append_key_nonlist_deep(self):
        filename = "/tmp/so-yaml_test-append.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "append", filename, "key1.child2.deep1", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The existing value for the given key is not a list. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_add_key(self):
        content = {}
        soyaml.addKey(content, "foo", 123)
        self.assertEqual(content, {"foo": 123})

        try:
            soyaml.addKey(content, "foo", "bar")
            self.assertFail("expected key error since key already exists")
        except KeyError:
            pass

        try:
            soyaml.addKey(content, "foo.bar", 123)
            self.assertFail("expected type error since key parent value is not a map")
        except TypeError:
            pass

        content = {}
        soyaml.addKey(content, "foo", "bar")
        self.assertEqual(content, {"foo": "bar"})

        soyaml.addKey(content, "badda.badda", "boom")
        self.assertEqual(content, {"foo": "bar", "badda": {"badda": "boom"}})

    def test_add_missing_arg(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "help"]
                soyaml.add(["file", "key"])
                sysmock.assert_called()
                self.assertIn("Missing filename, key arg, and/or value\n", mock_stderr.getvalue())

    def test_add(self):
        filename = "/tmp/so-yaml_test-add.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: abc }, key2: false, key3: [a,b,c]}")
        file.close()

        soyaml.add([filename, "key4", "d"])

        file = open(filename, "r")
        actual = file.read()
        file.close()
        expected = "key1:\n  child1: 123\n  child2: abc\nkey2: false\nkey3:\n- a\n- b\n- c\nkey4: d\n"
        self.assertEqual(actual, expected)

    def test_add_nested(self):
        filename = "/tmp/so-yaml_test-add.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: [a,b,c] }, key2: false, key3: [e,f,g]}")
        file.close()

        soyaml.add([filename, "key1.child3", "d"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2:\n  - a\n  - b\n  - c\n  child3: d\nkey2: false\nkey3:\n- e\n- f\n- g\n"
        self.assertEqual(actual, expected)

    def test_add_nested_deep(self):
        filename = "/tmp/so-yaml_test-add.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45 } }, key2: false, key3: [e,f,g]}")
        file.close()

        soyaml.add([filename, "key1.child2.deep2", "d"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2:\n    deep1: 45\n    deep2: d\nkey2: false\nkey3:\n- e\n- f\n- g\n"
        self.assertEqual(actual, expected)

    def test_replace_missing_arg(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "help"]
                soyaml.replace(["file", "key"])
                sysmock.assert_called()
                self.assertIn("Missing filename, key arg, and/or value\n", mock_stderr.getvalue())

    def test_replace(self):
        filename = "/tmp/so-yaml_test-add.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: abc }, key2: false, key3: [a,b,c]}")
        file.close()

        soyaml.replace([filename, "key2", True])

        file = open(filename, "r")
        actual = file.read()
        file.close()
        expected = "key1:\n  child1: 123\n  child2: abc\nkey2: true\nkey3:\n- a\n- b\n- c\n"
        self.assertEqual(actual, expected)

    def test_replace_nested(self):
        filename = "/tmp/so-yaml_test-add.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: [a,b,c] }, key2: false, key3: [e,f,g]}")
        file.close()

        soyaml.replace([filename, "key1.child2", "d"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2: d\nkey2: false\nkey3:\n- e\n- f\n- g\n"
        self.assertEqual(actual, expected)

    def test_replace_nested_deep(self):
        filename = "/tmp/so-yaml_test-add.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45 } }, key2: false, key3: [e,f,g]}")
        file.close()

        soyaml.replace([filename, "key1.child2.deep1", 46])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2:\n    deep1: 46\nkey2: false\nkey3:\n- e\n- f\n- g\n"
        self.assertEqual(actual, expected)

    def test_convert(self):
        self.assertEqual(soyaml.convertType("foo"), "foo")
        self.assertEqual(soyaml.convertType("foo.bar"), "foo.bar")
        self.assertEqual(soyaml.convertType("123"), 123)
        self.assertEqual(soyaml.convertType("0"), 0)
        self.assertEqual(soyaml.convertType("00"), "00")
        self.assertEqual(soyaml.convertType("0123"), "0123")
        self.assertEqual(soyaml.convertType("123.456"), 123.456)
        self.assertEqual(soyaml.convertType("0123.456"), "0123.456")
        self.assertEqual(soyaml.convertType("true"), True)
        self.assertEqual(soyaml.convertType("TRUE"), True)
        self.assertEqual(soyaml.convertType("false"), False)
        self.assertEqual(soyaml.convertType("FALSE"), False)
        self.assertEqual(soyaml.convertType(""), "")

    def test_get_int(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: 45 } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get([filename, "key1.child2.deep1"])
            self.assertEqual(result, 0)
            self.assertIn("45\n...", mock_stdout.getvalue())

    def test_get_str(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: \"hello\" } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get([filename, "key1.child2.deep1"])
            self.assertEqual(result, 0)
            self.assertIn("hello\n...", mock_stdout.getvalue())

    def test_get_list(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: \"hello\" } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get([filename, "key3"])
            self.assertEqual(result, 0)
            self.assertIn("- e\n- f\n- g\n", mock_stdout.getvalue())

    def test_get_dict(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: \"hello\" } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get([filename, "key1"])
            self.assertEqual(result, 0)
            self.assertIn("child1: 123\nchild2:\n  deep1: hello\n", mock_stdout.getvalue())

    def test_get_missing(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: 45 } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get([filename, "key1.child2.deep3"])
            self.assertEqual(result, 2)
            self.assertEqual("", mock_stdout.getvalue())

    def test_get_missing_parent(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: 45 } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get([filename, "key1.child3.deep3"])
            self.assertEqual(result, 2)
            self.assertEqual("", mock_stdout.getvalue())

    def test_get_usage(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                result = soyaml.get([])
                self.assertEqual(result, 1)
                self.assertIn("Missing filename or key arg", mock_stderr.getvalue())
                sysmock.assert_called_once_with(1)
