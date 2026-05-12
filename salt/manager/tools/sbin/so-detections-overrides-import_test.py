# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import json
import os
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from io import StringIO
from unittest.mock import MagicMock, patch

# The script has no .py extension, so importlib.import_module won't find it by
# name. SourceFileLoader loads source Python regardless of extension.
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "so-detections-overrides-import")
soi = SourceFileLoader("so_overrides_import", SCRIPT).load_module()


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

    def test_non_suricata_engine_skipped(self):
        # validate_override returns None for non-suricata engines (sigma is gated in main).
        self.assertIsNone(soi.validate_override({"type": "anything"}, "sigma"))


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


if __name__ == "__main__":
    unittest.main()
