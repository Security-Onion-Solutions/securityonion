# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from io import StringIO
from unittest.mock import MagicMock, patch

import requests

# The script has no .py extension; spec_from_file_location can't auto-detect a
# loader, so we hand it a SourceFileLoader explicitly. (load_module() is
# deprecated in 3.14 and slated for removal in 3.15.)
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "so-detections-overrides-import")
_loader = SourceFileLoader("so_overrides_import", SCRIPT)
_spec = importlib.util.spec_from_loader("so_overrides_import", _loader)
soi = importlib.util.module_from_spec(_spec)
_loader.exec_module(soi)


class TestValidateSuppress(unittest.TestCase):
    def test_valid(self):
        self.assertIsNone(soi.validate_override(
            {"type": "suppress", "track": "by_src", "ip": "1.2.3.4"}, "suricata"))

    def test_valid_var(self):
        self.assertIsNone(soi.validate_override(
            {"type": "suppress", "track": "by_either", "ip": "$HOME_NET"}, "suricata"))

    def test_valid_cidr(self):
        self.assertIsNone(soi.validate_override(
            {"type": "suppress", "track": "by_dst", "ip": "10.0.0.0/8"}, "suricata"))

    def test_valid_bracket_list(self):
        self.assertIsNone(soi.validate_override(
            {"type": "suppress", "track": "by_src", "ip": "[1.2.3.4,10.0.0.0/8]"}, "suricata"))

    def test_missing_ip(self):
        err = soi.validate_override({"type": "suppress", "track": "by_src"}, "suricata")
        self.assertIn("requires", err)

    def test_missing_track(self):
        err = soi.validate_override({"type": "suppress", "ip": "1.2.3.4"}, "suricata")
        self.assertIn("requires", err)

    def test_invalid_track(self):
        err = soi.validate_override(
            {"type": "suppress", "track": "by_both", "ip": "1.2.3.4"}, "suricata")
        self.assertIn("invalid track", err)

    def test_invalid_ip(self):
        err = soi.validate_override(
            {"type": "suppress", "track": "by_src", "ip": "not-an-ip"}, "suricata")
        self.assertIn("invalid IP", err)

    def test_unnecessary_field(self):
        err = soi.validate_override(
            {"type": "suppress", "track": "by_src", "ip": "1.2.3.4", "count": 5}, "suricata")
        self.assertIn("unnecessary fields", err)


class TestValidateThreshold(unittest.TestCase):
    def test_valid(self):
        self.assertIsNone(soi.validate_override({
            "type": "threshold", "track": "by_src",
            "thresholdType": "limit", "count": 10, "seconds": 60,
        }, "suricata"))

    def test_valid_by_both(self):
        self.assertIsNone(soi.validate_override({
            "type": "threshold", "track": "by_both",
            "thresholdType": "both", "count": 1, "seconds": 1,
        }, "suricata"))

    def test_track_by_either_invalid(self):
        err = soi.validate_override({
            "type": "threshold", "track": "by_either",
            "thresholdType": "limit", "count": 10, "seconds": 60,
        }, "suricata")
        self.assertIn("invalid track", err)

    def test_invalid_threshold_type(self):
        err = soi.validate_override({
            "type": "threshold", "track": "by_src",
            "thresholdType": "bogus", "count": 10, "seconds": 60,
        }, "suricata")
        self.assertIn("invalid thresholdType", err)

    def test_zero_count(self):
        err = soi.validate_override({
            "type": "threshold", "track": "by_src",
            "thresholdType": "limit", "count": 0, "seconds": 60,
        }, "suricata")
        self.assertIn("count", err)

    def test_negative_seconds(self):
        err = soi.validate_override({
            "type": "threshold", "track": "by_src",
            "thresholdType": "limit", "count": 10, "seconds": -1,
        }, "suricata")
        self.assertIn("seconds", err)

    def test_missing_field(self):
        err = soi.validate_override({
            "type": "threshold", "track": "by_src",
            "thresholdType": "limit", "count": 10,  # missing seconds
        }, "suricata")
        self.assertIn("requires", err)

    def test_unnecessary_field(self):
        err = soi.validate_override({
            "type": "threshold", "track": "by_src",
            "thresholdType": "limit", "count": 10, "seconds": 60,
            "regex": "foo",
        }, "suricata")
        self.assertIn("unnecessary fields", err)


class TestValidateModify(unittest.TestCase):
    def test_valid(self):
        self.assertIsNone(soi.validate_override(
            {"type": "modify", "regex": r"content:\"foo\"", "value": "content:bar"}, "suricata"))

    def test_invalid_regex(self):
        err = soi.validate_override(
            {"type": "modify", "regex": "(unbalanced", "value": "x"}, "suricata")
        self.assertIn("invalid regex", err)

    def test_missing_value(self):
        err = soi.validate_override({"type": "modify", "regex": "x"}, "suricata")
        self.assertIn("requires", err)

    def test_unnecessary_field(self):
        err = soi.validate_override(
            {"type": "modify", "regex": "x", "value": "y", "track": "by_src"}, "suricata")
        self.assertIn("unnecessary fields", err)


class TestValidateMisc(unittest.TestCase):
    def test_unknown_type(self):
        err = soi.validate_override({"type": "suppresss", "track": "by_src", "ip": "1.2.3.4"}, "suricata")
        self.assertIn("invalid type", err)

    def test_missing_type(self):
        err = soi.validate_override({"track": "by_src"}, "suricata")
        self.assertIn("type is required", err)


class TestValidateIP(unittest.TestCase):
    def test_plain_ipv4(self):
        self.assertIsNone(soi._validate_suricata_ip("1.2.3.4"))

    def test_plain_ipv6(self):
        self.assertIsNone(soi._validate_suricata_ip("::1"))

    def test_cidr(self):
        self.assertIsNone(soi._validate_suricata_ip("10.0.0.0/8"))

    def test_var(self):
        self.assertIsNone(soi._validate_suricata_ip("$CONCOURSEWORKERS"))

    def test_bracket_list(self):
        self.assertIsNone(soi._validate_suricata_ip("[1.2.3.4, 10.0.0.0/8]"))

    def test_bracket_list_bad_member(self):
        err = soi._validate_suricata_ip("[1.2.3.4,nope]")
        self.assertIn("invalid IP in list", err)

    def test_empty(self):
        self.assertIn("empty", soi._validate_suricata_ip(""))

    def test_invalid(self):
        self.assertIn("invalid", soi._validate_suricata_ip("999.999.999.999"))


class TestDedupeKey(unittest.TestCase):
    def test_suppress(self):
        a = {"type": "suppress", "track": "by_src", "ip": "1.2.3.4", "count": 99}
        b = {"type": "suppress", "track": "by_src", "ip": "1.2.3.4"}
        # count is irrelevant for suppress dedupe
        self.assertEqual(soi.dedupe_key(a), soi.dedupe_key(b))

    def test_suppress_differs_on_ip(self):
        a = {"type": "suppress", "track": "by_src", "ip": "1.2.3.4"}
        b = {"type": "suppress", "track": "by_src", "ip": "5.6.7.8"}
        self.assertNotEqual(soi.dedupe_key(a), soi.dedupe_key(b))

    def test_threshold(self):
        a = {"type": "threshold", "track": "by_src", "thresholdType": "limit",
             "count": 10, "seconds": 60, "ip": "ignored"}
        b = {"type": "threshold", "track": "by_src", "thresholdType": "limit",
             "count": 10, "seconds": 60}
        self.assertEqual(soi.dedupe_key(a), soi.dedupe_key(b))

    def test_threshold_differs_on_count(self):
        a = {"type": "threshold", "track": "by_src", "thresholdType": "limit",
             "count": 10, "seconds": 60}
        b = {"type": "threshold", "track": "by_src", "thresholdType": "limit",
             "count": 20, "seconds": 60}
        self.assertNotEqual(soi.dedupe_key(a), soi.dedupe_key(b))

    def test_modify(self):
        a = {"type": "modify", "regex": "x", "value": "y"}
        b = {"type": "modify", "regex": "x", "value": "y"}
        self.assertEqual(soi.dedupe_key(a), soi.dedupe_key(b))


class TestDescribe(unittest.TestCase):
    def test_suppress(self):
        s = soi.describe({"type": "suppress", "track": "by_src", "ip": "1.2.3.4"})
        self.assertIn("suppress", s)
        self.assertIn("by_src", s)
        self.assertIn("1.2.3.4", s)

    def test_threshold_includes_count(self):
        s = soi.describe({"type": "threshold", "track": "by_src",
                          "thresholdType": "limit", "count": 10, "seconds": 60})
        self.assertIn("count=10", s)
        self.assertIn("seconds=60", s)

    def test_modify(self):
        s = soi.describe({"type": "modify", "regex": "foo"})
        self.assertIn("modify", s)
        self.assertIn("foo", s)


class TestParseOverridesFile(unittest.TestCase):
    def _write(self, content):
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.close(fd)
        with open(path, "w") as f:
            f.write(content)
        self.addCleanup(os.unlink, path)
        return path

    def test_single_line(self):
        path = self._write('{"type":"suppress","track":"by_src","ip":"1.2.3.4"}')
        result = soi.parse_overrides_file(path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0]["type"], "suppress")
        self.assertEqual(result[0][1], 1)

    def test_ndjson(self):
        path = self._write(
            '{"type":"suppress","track":"by_src","ip":"1.2.3.4"}\n'
            '{"type":"suppress","track":"by_dst","ip":"5.6.7.8"}\n'
        )
        result = soi.parse_overrides_file(path)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[1][1], 2)

    def test_empty(self):
        path = self._write("")
        self.assertEqual(soi.parse_overrides_file(path), [])

    def test_blank_lines_skipped(self):
        path = self._write('\n{"type":"suppress","track":"by_src","ip":"1.2.3.4"}\n\n')
        result = soi.parse_overrides_file(path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][1], 2)  # line number reflects original position

    def test_invalid_raises(self):
        path = self._write("not json")
        with self.assertRaises(json.JSONDecodeError):
            soi.parse_overrides_file(path)


class TestCollectCustomVars(unittest.TestCase):
    def test_finds_custom(self):
        v = soi.collect_custom_vars({"ip": "$CONCOURSEWORKERS"})
        self.assertEqual(v, {"$CONCOURSEWORKERS"})

    def test_filters_builtins(self):
        v = soi.collect_custom_vars({"ip": "$HOME_NET"})
        self.assertEqual(v, set())

    def test_mixed(self):
        v = soi.collect_custom_vars({"ip": "[$HOME_NET,$MYNET]"})
        self.assertEqual(v, {"$MYNET"})

    def test_non_string_fields_ignored(self):
        v = soi.collect_custom_vars({"count": 10, "isEnabled": True})
        self.assertEqual(v, set())


class TestMakeSession(unittest.TestCase):
    def _write(self, content):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        with open(path, "w") as f:
            f.write(content)
        self.addCleanup(os.unlink, path)
        return path

    def test_valid_auth_file(self):
        path = self._write('user = "admin:secret"\n')
        session = soi.make_session(path)
        self.assertEqual(session.auth.username, "admin")
        self.assertEqual(session.auth.password, "secret")
        self.assertFalse(session.verify)

    def test_missing_user_line(self):
        path = self._write("# no user line here\n")
        with self.assertRaises(RuntimeError):
            soi.make_session(path)


class TestFindDetection(unittest.TestCase):
    def _session_with_response(self, payload):
        session = MagicMock()
        response = MagicMock()
        response.json.return_value = payload
        response.raise_for_status.return_value = None
        session.get.return_value = response
        return session

    def test_found(self):
        session = self._session_with_response({"hits": {"hits": [{
            "_id": "abc", "_index": "so-detection",
            "_source": {"so_detection": {"overrides": [{"type": "suppress"}]}},
        }]}})
        doc_id, idx, existing = soi.find_detection(session, "so-detection", "2049201", "suricata")
        self.assertEqual(doc_id, "abc")
        self.assertEqual(idx, "so-detection")
        self.assertEqual(len(existing), 1)

    def test_not_found(self):
        session = self._session_with_response({"hits": {"hits": []}})
        doc_id, idx, existing = soi.find_detection(session, "so-detection", "x", "suricata")
        self.assertIsNone(doc_id)
        self.assertIsNone(idx)
        self.assertIsNone(existing)

    def test_no_overrides_field(self):
        session = self._session_with_response({"hits": {"hits": [{
            "_id": "abc", "_index": "so-detection",
            "_source": {"so_detection": {}},
        }]}})
        _, _, existing = soi.find_detection(session, "so-detection", "x", "suricata")
        self.assertEqual(existing, [])

    def test_multiple_hits_warns(self):
        session = self._session_with_response({"hits": {"hits": [
            {"_id": "a", "_index": "i", "_source": {"so_detection": {"overrides": []}}},
            {"_id": "b", "_index": "i", "_source": {"so_detection": {"overrides": []}}},
        ]}})
        with patch("sys.stdout", new=StringIO()) as out:
            doc_id, _, _ = soi.find_detection(session, "i", "x", "suricata")
        self.assertEqual(doc_id, "a")
        self.assertIn("WARN", out.getvalue())


class TestUpdateOverrides(unittest.TestCase):
    def test_posts_to_update_endpoint(self):
        session = MagicMock()
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"result": "updated"}
        session.post.return_value = response

        result = soi.update_overrides(session, "so-detection", "abc", [{"type": "suppress"}])

        self.assertEqual(result, {"result": "updated"})
        url = session.post.call_args[0][0]
        self.assertIn("/_update/abc", url)
        body = session.post.call_args[1]["json"]
        self.assertEqual(body["doc"]["so_detection"]["overrides"], [{"type": "suppress"}])


class TestConfirmProceed(unittest.TestCase):
    def test_dry_run_skips_prompt(self):
        args = MagicMock(dry_run=True)
        with patch("sys.stdout", new=StringIO()):
            self.assertTrue(soi.confirm_proceed(args))

    def test_yes_input(self):
        args = MagicMock(dry_run=False)
        with patch("sys.stdout", new=StringIO()):
            with patch("builtins.input", return_value="yes"):
                self.assertTrue(soi.confirm_proceed(args))

    def test_yes_input_case_insensitive(self):
        args = MagicMock(dry_run=False)
        with patch("sys.stdout", new=StringIO()):
            with patch("builtins.input", return_value="YES"):
                self.assertTrue(soi.confirm_proceed(args))

    def test_no_input_aborts(self):
        args = MagicMock(dry_run=False)
        with patch("sys.stdout", new=StringIO()):
            with patch("builtins.input", return_value="no"):
                self.assertFalse(soi.confirm_proceed(args))

    def test_empty_input_aborts(self):
        args = MagicMock(dry_run=False)
        with patch("sys.stdout", new=StringIO()):
            with patch("builtins.input", return_value=""):
                self.assertFalse(soi.confirm_proceed(args))


class TestParseArgs(unittest.TestCase):
    def test_defaults(self):
        with patch.object(sys, "argv", ["cmd", "--source", "/some/path"]):
            args = soi.parse_args()
        self.assertEqual(args.source, "/some/path")
        self.assertEqual(args.engine, "suricata")
        self.assertFalse(args.dry_run)
        self.assertFalse(args.no_import_note)
        self.assertEqual(args.index, soi.DEFAULT_INDEX)

    def test_all_options(self):
        argv = ["cmd", "-s", "/x", "-e", "suricata", "-n",
                "--no-import-note", "-i", "alt-index"]
        with patch.object(sys, "argv", argv):
            args = soi.parse_args()
        self.assertEqual(args.source, "/x")
        self.assertTrue(args.dry_run)
        self.assertTrue(args.no_import_note)
        self.assertEqual(args.index, "alt-index")


class TestMain(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        # Stub make_session so tests don't need /opt/so/conf/elasticsearch/curl.config.
        p = patch.object(soi, "make_session", return_value=MagicMock())
        p.start()
        self.addCleanup(p.stop)

    def _write_file(self, public_id, overrides, ext="txt"):
        """Write an NDJSON override file. Entries may be dicts or raw strings (for malformed input)."""
        path = os.path.join(self.tmpdir, f"{public_id}.{ext}")
        with open(path, "w") as f:
            for o in overrides:
                f.write(o if isinstance(o, str) else json.dumps(o))
                f.write("\n")
        return path

    def _run_main(self, *extra_argv, input_response="yes"):
        """Run main() with stdout/stderr captured and input mocked. Returns (stdout, stderr, exit_code)."""
        argv = ["cmd", "--source", self.tmpdir, *extra_argv]
        out, err = StringIO(), StringIO()
        with patch.object(sys, "argv", argv), \
                patch("sys.stdout", new=out), \
                patch("sys.stderr", new=err), \
                patch("builtins.input", return_value=input_response):
            with self.assertRaises(SystemExit) as cm:
                soi.main()
        return out.getvalue(), err.getvalue(), cm.exception.code

    def test_source_dir_missing(self):
        argv = ["cmd", "--source", "/no/such/path/here"]
        err = StringIO()
        with patch.object(sys, "argv", argv), patch("sys.stderr", new=err):
            with self.assertRaises(SystemExit) as cm:
                soi.main()
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("source directory not found", err.getvalue())

    def test_no_files_found(self):
        out, _, code = self._run_main()
        self.assertEqual(code, 0)
        self.assertIn("No *.txt files found", out)

    def test_user_aborts(self):
        self._write_file("1001", [{"type": "suppress", "track": "by_src", "ip": "1.2.3.4"}])
        out, _, code = self._run_main(input_response="no")
        self.assertEqual(code, 1)
        self.assertIn("Aborted", out)

    def test_parse_error_increments_error(self):
        # Malformed JSON line — parse_overrides_file raises JSONDecodeError.
        self._write_file("1002", ["not json"])
        out, _, code = self._run_main("--dry-run")
        self.assertEqual(code, 1)  # invalid+error → non-zero
        self.assertIn("could not parse", out)
        self.assertIn("Errors:                    1", out)

    def test_empty_file_skipped(self):
        # Blank lines only — parse_overrides_file returns []; main reports "empty file" and continues.
        path = os.path.join(self.tmpdir, "1003.txt")
        with open(path, "w") as f:
            f.write("\n\n")
        out, _, code = self._run_main("--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("empty file", out)

    @patch.object(soi, "find_detection")
    def test_search_http_error(self, mock_find):
        mock_find.side_effect = requests.HTTPError("boom")
        self._write_file("1004", [{"type": "suppress", "track": "by_src", "ip": "1.2.3.4"}])
        out, _, code = self._run_main("--dry-run")
        self.assertEqual(code, 1)
        self.assertIn("search failed", out)

    @patch.object(soi, "find_detection")
    def test_no_detection_found(self, mock_find):
        mock_find.return_value = (None, None, None)
        self._write_file("1005", [{"type": "suppress", "track": "by_src", "ip": "1.2.3.4"}])
        out, _, code = self._run_main("--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("no detection found", out)
        self.assertIn("Skipped (no detection):    1", out)

    @patch.object(soi, "find_detection")
    def test_all_duplicates_no_update(self, mock_find):
        existing = [{"type": "suppress", "track": "by_src", "ip": "1.2.3.4"}]
        mock_find.return_value = ("doc1", "so-detection", existing)
        self._write_file("1006", [{"type": "suppress", "track": "by_src", "ip": "1.2.3.4"}])
        out, _, code = self._run_main("--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("SKIP", out)
        self.assertNotIn("DRY-RUN: would update", out)  # added_this_file == 0 branch

    @patch.object(soi, "update_overrides")
    @patch.object(soi, "find_detection")
    def test_happy_path_full(self, mock_find, mock_update):
        # Exercises: ADD, dedupe SKIP, INVALID, note prefix, UPDATE, custom-vars warning, exit=1 (invalid present)
        existing = [{"type": "suppress", "track": "by_src", "ip": "9.9.9.9"}]
        mock_find.return_value = ("doc1", "so-detection", existing)
        mock_update.return_value = {"result": "updated"}
        self._write_file("1007", [
            {"type": "suppress", "track": "by_src", "ip": "1.2.3.4"},                # ADD
            {"type": "suppress", "track": "by_src", "ip": "9.9.9.9"},                # SKIP (dupe of existing)
            {"type": "suppress", "track": "bogus",  "ip": "1.2.3.4"},                # INVALID
            {"type": "suppress", "track": "by_src", "ip": "$CONCOURSEWORKERS"},      # ADD + custom var
        ])
        out, _, code = self._run_main()
        self.assertEqual(code, 1)  # one invalid -> non-zero

        mock_update.assert_called_once()
        merged = mock_update.call_args[0][3]
        self.assertEqual(len(merged), 3)  # 1 existing + 2 new
        new_notes = [o.get("note", "") for o in merged if o.get("ip") in ("1.2.3.4", "$CONCOURSEWORKERS")]
        self.assertTrue(all(n.startswith("[Imported ") for n in new_notes))

        self.assertIn("ADD", out)
        self.assertIn("SKIP", out)
        self.assertIn("INVALID", out)
        self.assertIn("UPDATED", out)
        self.assertIn("$CONCOURSEWORKERS", out)

    @patch.object(soi, "update_overrides")
    @patch.object(soi, "find_detection")
    def test_no_import_note_preserves_note(self, mock_find, mock_update):
        mock_find.return_value = ("doc1", "so-detection", [])
        mock_update.return_value = {"result": "updated"}
        self._write_file("1008", [
            {"type": "suppress", "track": "by_src", "ip": "1.2.3.4", "note": "original"},
        ])
        _, _, code = self._run_main("--no-import-note")
        self.assertEqual(code, 0)
        merged = mock_update.call_args[0][3]
        self.assertEqual(merged[0]["note"], "original")  # no prefix applied

    @patch.object(soi, "find_detection")
    def test_dry_run_skips_update(self, mock_find):
        mock_find.return_value = ("doc1", "so-detection", [])
        self._write_file("1009", [{"type": "suppress", "track": "by_src", "ip": "1.2.3.4"}])
        with patch.object(soi, "update_overrides") as mock_update:
            out, _, code = self._run_main("--dry-run")
        self.assertEqual(code, 0)
        mock_update.assert_not_called()
        self.assertIn("DRY-RUN: would update", out)

    @patch.object(soi, "update_overrides")
    @patch.object(soi, "find_detection")
    def test_update_http_error(self, mock_find, mock_update):
        mock_find.return_value = ("doc1", "so-detection", [])
        mock_update.side_effect = requests.HTTPError("nope")
        self._write_file("1010", [{"type": "suppress", "track": "by_src", "ip": "1.2.3.4"}])
        out, _, code = self._run_main()
        self.assertEqual(code, 1)
        self.assertIn("update failed", out)


if __name__ == "__main__":
    unittest.main()
