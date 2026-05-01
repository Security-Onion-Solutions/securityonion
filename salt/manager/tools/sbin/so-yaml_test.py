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

    def test_convert_file(self):
        import tempfile
        import os

        # Create a temporary YAML file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("test:\n  - name: hi\n    color: blue\n")
            temp_file = f.name

        try:
            result = soyaml.convertType(f"file:{temp_file}")
            expected = {"test": [{"name": "hi", "color": "blue"}]}
            self.assertEqual(result, expected)
        finally:
            os.unlink(temp_file)

    def test_convert_file_nonexistent(self):
        with self.assertRaises(SystemExit) as cm:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                soyaml.convertType("file:/nonexistent/file.yaml")
                self.assertEqual(cm.exception.code, 1)
                self.assertIn("File '/nonexistent/file.yaml' does not exist.", mock_stderr.getvalue())

    def test_get_int(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: 45 } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get([filename, "key1.child2.deep1"])
            self.assertEqual(result, 0)
            self.assertIn("45\n...", mock_stdout.getvalue())

    def test_get_int_raw(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: 45 } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get(["-r", filename, "key1.child2.deep1"])
            self.assertEqual(result, 0)
            self.assertEqual("45\n", mock_stdout.getvalue())

    def test_get_str(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: \"hello\" } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get([filename, "key1.child2.deep1"])
            self.assertEqual(result, 0)
            self.assertIn("hello\n...", mock_stdout.getvalue())

    def test_get_str_raw(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: \"hello\" } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get(["-r", filename, "key1.child2.deep1"])
            self.assertEqual(result, 0)
            self.assertEqual("hello\n", mock_stdout.getvalue())

    def test_get_bool(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: 45 } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get([filename, "key2"])
            self.assertEqual(result, 0)
            self.assertIn("false\n...", mock_stdout.getvalue())

    def test_get_bool_raw(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: 45 } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get(["-r", filename, "key2"])
            self.assertEqual(result, 0)
            self.assertEqual("false\n", mock_stdout.getvalue())

    def test_get_dict_raw(self):
        with patch('sys.stdout', new=StringIO()) as mock_stdout:
            filename = "/tmp/so-yaml_test-get.yaml"
            file = open(filename, "w")
            file.write("{key1: { child1: 123, child2: { deep1: 45 } }, key2: false, key3: [e,f,g]}")
            file.close()

            result = soyaml.get(["-r", filename, "key1"])
            self.assertEqual(result, 0)
            self.assertIn("child1: 123", mock_stdout.getvalue())
            self.assertNotIn("...", mock_stdout.getvalue())

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


class TestRemoveListItem(unittest.TestCase):

    def test_removelistitem_missing_arg(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "help"]
                soyaml.removelistitem(["file", "key"])
                sysmock.assert_called()
                self.assertIn("Missing filename, key arg, or list item to remove", mock_stderr.getvalue())

    def test_removelistitem(self):
        filename = "/tmp/so-yaml_test-removelistitem.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: abc }, key2: false, key3: [a,b,c]}")
        file.close()

        soyaml.removelistitem([filename, "key3", "b"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2: abc\nkey2: false\nkey3:\n- a\n- c\n"
        self.assertEqual(actual, expected)

    def test_removelistitem_nested(self):
        filename = "/tmp/so-yaml_test-removelistitem.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: [a,b,c] }, key2: false, key3: [e,f,g]}")
        file.close()

        soyaml.removelistitem([filename, "key1.child2", "b"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2:\n  - a\n  - c\nkey2: false\nkey3:\n- e\n- f\n- g\n"
        self.assertEqual(actual, expected)

    def test_removelistitem_nested_deep(self):
        filename = "/tmp/so-yaml_test-removelistitem.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        soyaml.removelistitem([filename, "key1.child2.deep2", "b"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2:\n    deep1: 45\n    deep2:\n    - a\n    - c\nkey2: false\nkey3:\n- e\n- f\n- g\n"
        self.assertEqual(actual, expected)

    def test_removelistitem_item_not_in_list(self):
        filename = "/tmp/so-yaml_test-removelistitem.yaml"
        file = open(filename, "w")
        file.write("{key1: [a,b,c]}")
        file.close()

        soyaml.removelistitem([filename, "key1", "d"])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n- a\n- b\n- c\n"
        self.assertEqual(actual, expected)

    def test_removelistitem_key_noexist(self):
        filename = "/tmp/so-yaml_test-removelistitem.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "removelistitem", filename, "key4", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The key provided does not exist. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_removelistitem_key_noexist_deep(self):
        filename = "/tmp/so-yaml_test-removelistitem.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "removelistitem", filename, "key1.child2.deep3", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The key provided does not exist. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_removelistitem_key_nonlist(self):
        filename = "/tmp/so-yaml_test-removelistitem.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "removelistitem", filename, "key1", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The existing value for the given key is not a list. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_removelistitem_key_nonlist_deep(self):
        filename = "/tmp/so-yaml_test-removelistitem.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [a,b,c] } }, key2: false, key3: [e,f,g]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "removelistitem", filename, "key1.child2.deep1", "h"]
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The existing value for the given key is not a list. No action was taken on the file.\n", mock_stderr.getvalue())


class TestAppendListObject(unittest.TestCase):

    def test_appendlistobject_missing_arg(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "help"]
                soyaml.appendlistobject(["file", "key"])
                sysmock.assert_called()
                self.assertIn("Missing filename, key arg, or JSON object to append", mock_stderr.getvalue())

    def test_appendlistobject(self):
        filename = "/tmp/so-yaml_test-appendlistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123 }, key2: [{name: item1, value: 10}]}")
        file.close()

        json_obj = '{"name": "item2", "value": 20}'
        soyaml.appendlistobject([filename, "key2", json_obj])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\nkey2:\n- name: item1\n  value: 10\n- name: item2\n  value: 20\n"
        self.assertEqual(actual, expected)

    def test_appendlistobject_nested(self):
        filename = "/tmp/so-yaml_test-appendlistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: [{name: a, id: 1}], child2: abc }, key2: false}")
        file.close()

        json_obj = '{"name": "b", "id": 2}'
        soyaml.appendlistobject([filename, "key1.child1", json_obj])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        # YAML doesn't guarantee key order in dictionaries, so check for content
        self.assertIn("child1:", actual)
        self.assertIn("name: a", actual)
        self.assertIn("id: 1", actual)
        self.assertIn("name: b", actual)
        self.assertIn("id: 2", actual)
        self.assertIn("child2: abc", actual)
        self.assertIn("key2: false", actual)

    def test_appendlistobject_nested_deep(self):
        filename = "/tmp/so-yaml_test-appendlistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [{x: 1}] } }, key2: false}")
        file.close()

        json_obj = '{"x": 2, "y": 3}'
        soyaml.appendlistobject([filename, "key1.child2.deep2", json_obj])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2:\n    deep1: 45\n    deep2:\n    - x: 1\n    - x: 2\n      y: 3\nkey2: false\n"
        self.assertEqual(actual, expected)

    def test_appendlistobject_invalid_json(self):
        filename = "/tmp/so-yaml_test-appendlistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: [{name: item1}]}")
        file.close()

        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            result = soyaml.appendlistobject([filename, "key1", "{invalid json"])
            self.assertEqual(result, 1)
            self.assertIn("Invalid JSON string:", mock_stderr.getvalue())

    def test_appendlistobject_not_dict(self):
        filename = "/tmp/so-yaml_test-appendlistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: [{name: item1}]}")
        file.close()

        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            # Try to append an array instead of an object
            result = soyaml.appendlistobject([filename, "key1", "[1, 2, 3]"])
            self.assertEqual(result, 1)
            self.assertIn("The JSON string must represent an object (dictionary)", mock_stderr.getvalue())

    def test_appendlistobject_not_dict_primitive(self):
        filename = "/tmp/so-yaml_test-appendlistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: [{name: item1}]}")
        file.close()

        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            # Try to append a primitive value
            result = soyaml.appendlistobject([filename, "key1", "123"])
            self.assertEqual(result, 1)
            self.assertIn("The JSON string must represent an object (dictionary)", mock_stderr.getvalue())

    def test_appendlistobject_key_noexist(self):
        filename = "/tmp/so-yaml_test-appendlistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: [{name: item1}]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "appendlistobject", filename, "key2", '{"name": "item2"}']
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The key provided does not exist. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_appendlistobject_key_noexist_deep(self):
        filename = "/tmp/so-yaml_test-appendlistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: [{name: a}] }}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "appendlistobject", filename, "key1.child2", '{"name": "b"}']
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The key provided does not exist. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_appendlistobject_key_nonlist(self):
        filename = "/tmp/so-yaml_test-appendlistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123 }}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "appendlistobject", filename, "key1", '{"name": "item"}']
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The existing value for the given key is not a list. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_appendlistobject_key_nonlist_deep(self):
        filename = "/tmp/so-yaml_test-appendlistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45 } }}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "appendlistobject", filename, "key1.child2.deep1", '{"name": "item"}']
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The existing value for the given key is not a list. No action was taken on the file.\n", mock_stderr.getvalue())


class TestReplaceListObject(unittest.TestCase):

    def test_replacelistobject_missing_arg(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "help"]
                soyaml.replacelistobject(["file", "key", "field"])
                sysmock.assert_called()
                self.assertIn("Missing filename, key arg, condition field, condition value, or JSON object", mock_stderr.getvalue())

    def test_replacelistobject(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: [{name: item1, value: 10}, {name: item2, value: 20}]}")
        file.close()

        json_obj = '{"name": "item2", "value": 25, "extra": "field"}'
        soyaml.replacelistobject([filename, "key1", "name", "item2", json_obj])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n- name: item1\n  value: 10\n- extra: field\n  name: item2\n  value: 25\n"
        self.assertEqual(actual, expected)

    def test_replacelistobject_nested(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: [{id: '1', status: active}, {id: '2', status: inactive}] }}")
        file.close()

        json_obj = '{"id": "2", "status": "active", "updated": true}'
        soyaml.replacelistobject([filename, "key1.child1", "id", "2", json_obj])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1:\n  - id: '1'\n    status: active\n  - id: '2'\n    status: active\n    updated: true\n"
        self.assertEqual(actual, expected)

    def test_replacelistobject_nested_deep(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45, deep2: [{name: a, val: 1}, {name: b, val: 2}] } }}")
        file.close()

        json_obj = '{"name": "b", "val": 99}'
        soyaml.replacelistobject([filename, "key1.child2.deep2", "name", "b", json_obj])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n  child1: 123\n  child2:\n    deep1: 45\n    deep2:\n    - name: a\n      val: 1\n    - name: b\n      val: 99\n"
        self.assertEqual(actual, expected)

    def test_replacelistobject_invalid_json(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: [{name: item1}]}")
        file.close()

        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            result = soyaml.replacelistobject([filename, "key1", "name", "item1", "{invalid json"])
            self.assertEqual(result, 1)
            self.assertIn("Invalid JSON string:", mock_stderr.getvalue())

    def test_replacelistobject_not_dict(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: [{name: item1}]}")
        file.close()

        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            result = soyaml.replacelistobject([filename, "key1", "name", "item1", "[1, 2, 3]"])
            self.assertEqual(result, 1)
            self.assertIn("The JSON string must represent an object (dictionary)", mock_stderr.getvalue())

    def test_replacelistobject_condition_not_found(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: [{name: item1, value: 10}, {name: item2, value: 20}]}")
        file.close()

        with patch('sys.stderr', new=StringIO()) as mock_stderr:
            json_obj = '{"name": "item3", "value": 30}'
            result = soyaml.replacelistobject([filename, "key1", "name", "item3", json_obj])
            self.assertEqual(result, 1)
            self.assertIn("No list item found with name=item3", mock_stderr.getvalue())

        # Verify file was not modified
        file = open(filename, "r")
        actual = file.read()
        file.close()
        self.assertIn("item1", actual)
        self.assertIn("item2", actual)
        self.assertNotIn("item3", actual)

    def test_replacelistobject_key_noexist(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: [{name: item1}]}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "replacelistobject", filename, "key2", "name", "item1", '{"name": "item2"}']
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The key provided does not exist. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_replacelistobject_key_noexist_deep(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: [{name: a}] }}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "replacelistobject", filename, "key1.child2", "name", "a", '{"name": "b"}']
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The key provided does not exist. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_replacelistobject_key_nonlist(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123 }}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "replacelistobject", filename, "key1", "name", "item", '{"name": "item"}']
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The existing value for the given key is not a list. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_replacelistobject_key_nonlist_deep(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: { child1: 123, child2: { deep1: 45 } }}")
        file.close()

        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                sys.argv = ["cmd", "replacelistobject", filename, "key1.child2.deep1", "name", "item", '{"name": "item"}']
                soyaml.main()
                sysmock.assert_called()
                self.assertEqual("The existing value for the given key is not a list. No action was taken on the file.\n", mock_stderr.getvalue())

    def test_replacelistobject_string_condition_value(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: [{name: item1, value: 10}, {name: item2, value: 20}]}")
        file.close()

        json_obj = '{"name": "item1", "value": 15}'
        soyaml.replacelistobject([filename, "key1", "name", "item1", json_obj])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n- name: item1\n  value: 15\n- name: item2\n  value: 20\n"
        self.assertEqual(actual, expected)

    def test_replacelistobject_numeric_condition_value(self):
        filename = "/tmp/so-yaml_test-replacelistobject.yaml"
        file = open(filename, "w")
        file.write("{key1: [{id: '1', status: active}, {id: '2', status: inactive}]}")
        file.close()

        json_obj = '{"id": "1", "status": "updated"}'
        soyaml.replacelistobject([filename, "key1", "id", "1", json_obj])

        file = open(filename, "r")
        actual = file.read()
        file.close()

        expected = "key1:\n- id: '1'\n  status: updated\n- id: '2'\n  status: inactive\n"
        self.assertEqual(actual, expected)


class TestLoadYaml(unittest.TestCase):

    def test_load_yaml_missing_file(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                soyaml.loadYaml("/tmp/so-yaml_test-does-not-exist.yaml")
                sysmock.assert_called_with(1)
                self.assertIn("File not found:", mock_stderr.getvalue())

    def test_load_yaml_read_error(self):
        with patch('sys.exit', new=MagicMock()) as sysmock:
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                with patch('builtins.open', side_effect=PermissionError("denied")):
                    soyaml.loadYaml("/tmp/so-yaml_test-unreadable.yaml")
                    sysmock.assert_called_with(1)
                    self.assertIn("Error reading file", mock_stderr.getvalue())


class TestPurge(unittest.TestCase):

    def test_purge_missing_arg(self):
        # showUsage calls sys.exit(1); patch it like the other tests do.
        with patch('sys.exit', new=MagicMock()):
            with patch('sys.stderr', new=StringIO()) as mock_stderr:
                rc = soyaml.purge([])
                self.assertEqual(rc, 1)
                self.assertIn("Missing filename", mock_stderr.getvalue())

    def test_purge_existing_file(self):
        filename = "/tmp/so-yaml_test_purge.yaml"
        with open(filename, "w") as f:
            f.write("key: value\n")
        # Disable PG mirror so the test doesn't shell out to docker.
        with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', False):
            rc = soyaml.purge([filename])
        self.assertEqual(rc, 0)
        import os as _os
        self.assertFalse(_os.path.exists(filename))

    def test_purge_missing_file_idempotent(self):
        filename = "/tmp/so-yaml_test_purge_missing.yaml"
        import os as _os
        if _os.path.exists(filename):
            _os.remove(filename)
        with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', False):
            rc = soyaml.purge([filename])
        self.assertEqual(rc, 0)


class TestSoYamlPostgres(unittest.TestCase):
    """Tests the path-locator and write/purge contract of the dual-write
    backend module without actually contacting Postgres."""

    def setUp(self):
        import importlib
        self.mod = importlib.import_module("so_yaml_postgres")

    def test_locate_global_soc(self):
        scope, role, mid, path = self.mod.locate(
            "/opt/so/saltstack/local/pillar/soc/soc_soc.sls")
        self.assertEqual(scope, "global")
        self.assertIsNone(role)
        self.assertIsNone(mid)
        self.assertEqual(path, "soc.soc_soc")

    def test_locate_global_advanced(self):
        scope, role, mid, path = self.mod.locate(
            "/opt/so/saltstack/local/pillar/soc/adv_soc.sls")
        self.assertEqual(scope, "global")
        self.assertEqual(path, "soc.adv_soc")

    def test_locate_minion(self):
        scope, role, mid, path = self.mod.locate(
            "/opt/so/saltstack/local/pillar/minions/h1_sensor.sls")
        self.assertEqual(scope, "minion")
        self.assertEqual(mid, "h1_sensor")
        self.assertEqual(path, "minions.h1_sensor")

    def test_locate_minion_advanced(self):
        scope, role, mid, path = self.mod.locate(
            "/opt/so/saltstack/local/pillar/minions/adv_h1_sensor.sls")
        self.assertEqual(scope, "minion")
        self.assertEqual(mid, "h1_sensor")
        self.assertEqual(path, "minions.adv_h1_sensor")

    def test_locate_skip_secrets(self):
        with self.assertRaises(self.mod.SkipPath):
            self.mod.locate("/opt/so/saltstack/local/pillar/secrets.sls")

    def test_locate_skip_postgres_auth(self):
        with self.assertRaises(self.mod.SkipPath):
            self.mod.locate("/opt/so/saltstack/local/pillar/postgres/auth.sls")

    def test_locate_skip_mine_driven(self):
        with self.assertRaises(self.mod.SkipPath):
            self.mod.locate("/opt/so/saltstack/local/pillar/elasticsearch/nodes.sls")

    def test_locate_skip_top(self):
        with self.assertRaises(self.mod.SkipPath):
            self.mod.locate("/opt/so/saltstack/local/pillar/top.sls")

    def test_locate_skip_unrelated(self):
        with self.assertRaises(self.mod.SkipPath):
            self.mod.locate("/etc/hostname")

    def test_pg_str_escapes(self):
        self.assertEqual(self.mod._pg_str("a'b"), "'a''b'")
        self.assertEqual(self.mod._pg_str(None), "NULL")

    def test_conflict_target(self):
        self.assertIn("scope='global'", self.mod._conflict_target("global"))
        self.assertIn("scope='role'", self.mod._conflict_target("role"))
        self.assertIn("scope='minion'", self.mod._conflict_target("minion"))
        with self.assertRaises(ValueError):
            self.mod._conflict_target("bogus")

    def test_write_yaml_skips_disk_only_path(self):
        with patch.object(self.mod, '_is_enabled', return_value=True):
            ok, msg = self.mod.write_yaml(
                "/opt/so/saltstack/local/pillar/secrets.sls",
                {"secrets": {"foo": "bar"}})
        self.assertFalse(ok)
        self.assertIn("disk-only", msg)

    def test_write_yaml_unreachable(self):
        with patch.object(self.mod, '_is_enabled', return_value=False):
            ok, msg = self.mod.write_yaml(
                "/opt/so/saltstack/local/pillar/soc/soc_soc.sls",
                {"soc": {"foo": "bar"}})
        self.assertFalse(ok)
        self.assertEqual(msg, "postgres unreachable")

    def test_is_pg_managed_true(self):
        self.assertTrue(self.mod.is_pg_managed(
            "/opt/so/saltstack/local/pillar/minions/h1_sensor.sls"))
        self.assertTrue(self.mod.is_pg_managed(
            "/opt/so/saltstack/local/pillar/soc/soc_soc.sls"))

    def test_is_pg_managed_false_for_bootstrap(self):
        self.assertFalse(self.mod.is_pg_managed(
            "/opt/so/saltstack/local/pillar/secrets.sls"))
        self.assertFalse(self.mod.is_pg_managed(
            "/opt/so/saltstack/local/pillar/postgres/auth.sls"))
        self.assertFalse(self.mod.is_pg_managed(
            "/opt/so/saltstack/local/pillar/elasticsearch/nodes.sls"))

    def test_read_yaml_unreachable(self):
        with patch.object(self.mod, '_is_enabled', return_value=False):
            self.assertIsNone(self.mod.read_yaml(
                "/opt/so/saltstack/local/pillar/soc/soc_soc.sls"))

    def test_read_yaml_skips_disk_only(self):
        with patch.object(self.mod, '_is_enabled', return_value=True):
            with self.assertRaises(self.mod.SkipPath):
                self.mod.read_yaml(
                    "/opt/so/saltstack/local/pillar/secrets.sls")

    def test_read_yaml_returns_data(self):
        with patch.object(self.mod, '_is_enabled', return_value=True):
            with patch.object(self.mod, '_docker_psql',
                              return_value='{"soc": {"foo": "bar"}}\n'):
                data = self.mod.read_yaml(
                    "/opt/so/saltstack/local/pillar/soc/soc_soc.sls")
        self.assertEqual(data, {"soc": {"foo": "bar"}})

    def test_read_yaml_returns_none_when_no_row(self):
        with patch.object(self.mod, '_is_enabled', return_value=True):
            with patch.object(self.mod, '_docker_psql', return_value=''):
                data = self.mod.read_yaml(
                    "/opt/so/saltstack/local/pillar/soc/soc_soc.sls")
        self.assertIsNone(data)

    def test_read_yaml_minion_query_shape(self):
        captured = {}

        def fake_psql(sql):
            captured['sql'] = sql
            return '{"host": {"mainip": "10.0.0.1"}}'

        with patch.object(self.mod, '_is_enabled', return_value=True):
            with patch.object(self.mod, '_docker_psql', side_effect=fake_psql):
                data = self.mod.read_yaml(
                    "/opt/so/saltstack/local/pillar/minions/h1_sensor.sls")
        self.assertEqual(data, {"host": {"mainip": "10.0.0.1"}})
        self.assertIn("scope='minion'", captured['sql'])
        self.assertIn("'h1_sensor'", captured['sql'])
        self.assertIn("'minions.h1_sensor'", captured['sql'])

    def test_is_enabled_public_alias(self):
        with patch.object(self.mod, '_is_enabled', return_value=True):
            self.assertTrue(self.mod.is_enabled())
        with patch.object(self.mod, '_is_enabled', return_value=False):
            self.assertFalse(self.mod.is_enabled())


class TestSoYamlBackendMode(unittest.TestCase):
    """Tests so-yaml's backend-mode resolution and PG-canonical routing
    for read/write/purge. The PG calls themselves are stubbed; what we're
    asserting is that the right backend is chosen for each (mode, path)
    combination."""

    def test_resolve_mode_env_overrides_file(self):
        with patch.dict('os.environ', {'SO_YAML_BACKEND': 'postgres'}):
            self.assertEqual(soyaml._resolveBackendMode(), 'postgres')
        with patch.dict('os.environ', {'SO_YAML_BACKEND': 'disk'}):
            self.assertEqual(soyaml._resolveBackendMode(), 'disk')

    def test_resolve_mode_invalid_env_falls_back(self):
        with patch.dict('os.environ', {'SO_YAML_BACKEND': 'garbage'}, clear=False):
            with patch('builtins.open', side_effect=IOError):
                self.assertEqual(soyaml._resolveBackendMode(), 'dual')

    def test_resolve_mode_default_dual(self):
        env = {k: v for k, v in __import__('os').environ.items()
               if k != 'SO_YAML_BACKEND'}
        with patch.dict('os.environ', env, clear=True):
            with patch('builtins.open', side_effect=IOError):
                self.assertEqual(soyaml._resolveBackendMode(), 'dual')

    def test_is_pg_managed_proxies(self):
        with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', True):
            self.assertTrue(soyaml._isPgManaged(
                "/opt/so/saltstack/local/pillar/minions/h1_sensor.sls"))
            self.assertFalse(soyaml._isPgManaged(
                "/opt/so/saltstack/local/pillar/secrets.sls"))

    def test_is_pg_managed_false_when_module_unavailable(self):
        with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', False):
            self.assertFalse(soyaml._isPgManaged(
                "/opt/so/saltstack/local/pillar/minions/h1_sensor.sls"))

    def test_load_yaml_postgres_mode_reads_pg(self):
        with patch.object(soyaml, '_BACKEND_MODE', 'postgres'):
            with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', True):
                with patch.object(soyaml.so_yaml_postgres, 'is_pg_managed',
                                  return_value=True):
                    with patch.object(soyaml.so_yaml_postgres, 'read_yaml',
                                      return_value={"a": 1}):
                        result = soyaml.loadYaml(
                            "/opt/so/saltstack/local/pillar/soc/soc_soc.sls")
        self.assertEqual(result, {"a": 1})

    def test_load_yaml_postgres_mode_returns_empty_when_no_row(self):
        with patch.object(soyaml, '_BACKEND_MODE', 'postgres'):
            with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', True):
                with patch.object(soyaml.so_yaml_postgres, 'is_pg_managed',
                                  return_value=True):
                    with patch.object(soyaml.so_yaml_postgres, 'read_yaml',
                                      return_value=None):
                        result = soyaml.loadYaml(
                            "/opt/so/saltstack/local/pillar/soc/soc_soc.sls")
        self.assertEqual(result, {})

    def test_load_yaml_postgres_mode_reads_disk_for_bootstrap(self):
        import tempfile, os as _os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("foo: bar\n")
            tmp = f.name
        try:
            with patch.object(soyaml, '_BACKEND_MODE', 'postgres'):
                with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', True):
                    with patch.object(soyaml.so_yaml_postgres,
                                      'is_pg_managed', return_value=False):
                        result = soyaml.loadYaml(tmp)
            self.assertEqual(result, {"foo": "bar"})
        finally:
            _os.unlink(tmp)

    def test_write_yaml_postgres_mode_skips_disk(self):
        import tempfile, os as _os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            tmp = f.name
        _os.unlink(tmp)
        try:
            with patch.object(soyaml, '_BACKEND_MODE', 'postgres'):
                with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', True):
                    with patch.object(soyaml.so_yaml_postgres, 'is_pg_managed',
                                      return_value=True):
                        with patch.object(soyaml.so_yaml_postgres, 'write_yaml',
                                          return_value=(True, 'ok')) as mock_w:
                            soyaml.writeYaml(tmp, {"x": 1})
            self.assertFalse(_os.path.exists(tmp))
            mock_w.assert_called_once()
        finally:
            if _os.path.exists(tmp):
                _os.unlink(tmp)

    def test_write_yaml_postgres_mode_failure_is_fatal(self):
        with patch.object(soyaml, '_BACKEND_MODE', 'postgres'):
            with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', True):
                with patch.object(soyaml.so_yaml_postgres, 'is_pg_managed',
                                  return_value=True):
                    with patch.object(soyaml.so_yaml_postgres, 'write_yaml',
                                      return_value=(False, 'pg write failed: connection refused')):
                        with patch('sys.exit', new=MagicMock()) as sysmock:
                            with patch('sys.stderr', new=StringIO()) as mock_err:
                                soyaml.writeYaml(
                                    "/opt/so/saltstack/local/pillar/soc/soc_soc.sls",
                                    {"x": 1})
        sysmock.assert_called_with(1)

    def test_write_yaml_disk_mode_skips_pg(self):
        import tempfile, os as _os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            tmp = f.name
        try:
            with patch.object(soyaml, '_BACKEND_MODE', 'disk'):
                with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', True):
                    with patch.object(soyaml.so_yaml_postgres, 'write_yaml') as mock_w:
                        soyaml.writeYaml(tmp, {"x": 1})
            mock_w.assert_not_called()
            with open(tmp) as f:
                self.assertIn('x: 1', f.read())
        finally:
            _os.unlink(tmp)

    def test_purge_postgres_mode_calls_pg_only(self):
        import tempfile, os as _os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            tmp = f.name
        _os.unlink(tmp)
        with patch.object(soyaml, '_BACKEND_MODE', 'postgres'):
            with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', True):
                with patch.object(soyaml.so_yaml_postgres, 'is_pg_managed',
                                  return_value=True):
                    with patch.object(soyaml.so_yaml_postgres, 'purge_yaml',
                                      return_value=(True, 'ok')) as mock_p:
                        rc = soyaml.purgeFile(tmp)
        self.assertEqual(rc, 0)
        mock_p.assert_called_once()

    def test_purge_postgres_mode_failure_returns_nonzero(self):
        with patch.object(soyaml, '_BACKEND_MODE', 'postgres'):
            with patch.object(soyaml, '_SO_YAML_PG_AVAILABLE', True):
                with patch.object(soyaml.so_yaml_postgres, 'is_pg_managed',
                                  return_value=True):
                    with patch.object(soyaml.so_yaml_postgres, 'purge_yaml',
                                      return_value=(False, 'pg purge failed: x')):
                        with patch('sys.stderr', new=StringIO()):
                            rc = soyaml.purgeFile(
                                "/opt/so/saltstack/local/pillar/minions/h1_sensor.sls")
        self.assertEqual(rc, 1)
