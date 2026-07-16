# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import hashlib
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

import rules_beacon


class TestRulesBeacon(unittest.TestCase):

    def setUp(self):
        # Isolate all on-disk state (watermarks and the dirs we fingerprint) in a
        # throwaway tree, and point WATERMARK_DIR at it so the real read/write
        # helpers run against actual files.
        self.tmpdir = tempfile.mkdtemp()
        self.state = os.path.join(self.tmpdir, 'state')
        patcher = patch.object(rules_beacon, 'WATERMARK_DIR', self.state)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_dir(self, name, files=None):
        path = os.path.join(self.tmpdir, name)
        os.makedirs(path, exist_ok=True)
        for fname, content in (files or {}).items():
            with open(os.path.join(path, fname), 'w') as f:
                f.write(content)
        return path

    # -- trivial contract -------------------------------------------------

    def test_virtual_returns_true(self):
        self.assertTrue(rules_beacon.__virtual__())

    def test_validate_returns_valid(self):
        self.assertEqual(rules_beacon.validate({}), (True, 'valid'))

    # -- _paths_from_config -----------------------------------------------

    def test_paths_from_config_list_of_dicts(self):
        config = [{'interval': 10}, {'paths': {'/a': 'suricata', '/b': 'strelka'}}]
        self.assertEqual(
            rules_beacon._paths_from_config(config),
            {'/a': 'suricata', '/b': 'strelka'},
        )

    def test_paths_from_config_plain_dict(self):
        self.assertEqual(
            rules_beacon._paths_from_config({'paths': {'/a': 'suricata'}}),
            {'/a': 'suricata'},
        )

    def test_paths_from_config_skips_non_dict_items(self):
        self.assertEqual(rules_beacon._paths_from_config(['bogus', 42]), {})

    def test_paths_from_config_paths_not_a_dict(self):
        self.assertEqual(rules_beacon._paths_from_config({'paths': 'nope'}), {})

    def test_paths_from_config_unexpected_type(self):
        self.assertEqual(rules_beacon._paths_from_config('nonsense'), {})

    # -- _excluded --------------------------------------------------------

    def test_excluded_matches_temp_and_editor_files(self):
        for pathname in ('/rules/foo.swp', '/rules/foo~', '/rules/4913', '/rules/.#foo'):
            self.assertTrue(rules_beacon._excluded(pathname), pathname)

    def test_excluded_allows_real_rule_files(self):
        self.assertFalse(rules_beacon._excluded('/rules/suricata.rules'))

    # -- _fingerprint -----------------------------------------------------

    def test_fingerprint_missing_dir_is_empty_tree_digest(self):
        missing = os.path.join(self.tmpdir, 'does-not-exist')
        self.assertEqual(rules_beacon._fingerprint(missing), hashlib.sha1().hexdigest())

    def test_fingerprint_changes_when_content_changes(self):
        d = self._make_dir('rules', {'a.rules': 'alert'})
        before = rules_beacon._fingerprint(d)
        with open(os.path.join(d, 'a.rules'), 'w') as f:
            f.write('alert tcp any any -> any any')  # different size
        self.assertNotEqual(rules_beacon._fingerprint(d), before)

    def test_fingerprint_ignores_excluded_files(self):
        d = self._make_dir('rules', {'a.rules': 'alert'})
        before = rules_beacon._fingerprint(d)
        with open(os.path.join(d, 'a.rules.swp'), 'w') as f:
            f.write('editor swap')
        self.assertEqual(rules_beacon._fingerprint(d), before)

    def test_fingerprint_skips_unstatable_entries(self):
        # A dangling symlink appears in os.walk's file list but os.stat raises
        # OSError, exercising the except-continue path.
        d = self._make_dir('rules', {'a.rules': 'alert'})
        good = rules_beacon._fingerprint(d)
        os.symlink(os.path.join(d, 'missing-target'), os.path.join(d, 'broken.link'))
        self.assertEqual(rules_beacon._fingerprint(d), good)

    # -- _read_watermark / _write_watermark -------------------------------

    def test_watermark_round_trip(self):
        rules_beacon._write_watermark('suricata', 'deadbeef')
        self.assertEqual(rules_beacon._read_watermark('suricata'), 'deadbeef')

    def test_read_watermark_missing_returns_none(self):
        self.assertIsNone(rules_beacon._read_watermark('suricata'))

    def test_read_watermark_empty_file_returns_none(self):
        os.makedirs(self.state, exist_ok=True)
        with open(rules_beacon._watermark_file('suricata'), 'w') as f:
            f.write('')
        self.assertIsNone(rules_beacon._read_watermark('suricata'))

    def test_write_watermark_swallows_oserror(self):
        with patch.object(rules_beacon.os, 'makedirs', side_effect=OSError):
            rules_beacon._write_watermark('suricata', 'deadbeef')
        self.assertIsNone(rules_beacon._read_watermark('suricata'))

    # -- beacon -----------------------------------------------------------

    def _config(self, mapping):
        return [{'paths': mapping}]

    def test_beacon_seeds_first_run_and_emits_nothing(self):
        with patch.object(rules_beacon, '_fingerprint', return_value='hash1'), \
             patch.object(rules_beacon, '_read_watermark', return_value=None), \
             patch.object(rules_beacon, '_write_watermark') as mock_write:
            result = rules_beacon.beacon(self._config({'/rules/suricata': 'suricata'}))
        self.assertEqual(result, [])
        mock_write.assert_called_once_with('suricata', 'hash1')

    def test_beacon_emits_on_change(self):
        with patch.object(rules_beacon, '_fingerprint', return_value='newhash'), \
             patch.object(rules_beacon, '_read_watermark', return_value='oldhash'), \
             patch.object(rules_beacon, '_write_watermark') as mock_write:
            result = rules_beacon.beacon(self._config({'/rules/suricata': 'suricata'}))
        self.assertEqual(result, [{'tag': 'suricata', 'path': '/rules/suricata'}])
        mock_write.assert_called_once_with('suricata', 'newhash')

    def test_beacon_no_change_emits_nothing(self):
        with patch.object(rules_beacon, '_fingerprint', return_value='samehash'), \
             patch.object(rules_beacon, '_read_watermark', return_value='samehash'), \
             patch.object(rules_beacon, '_write_watermark') as mock_write:
            result = rules_beacon.beacon(self._config({'/rules/suricata': 'suricata'}))
        self.assertEqual(result, [])
        mock_write.assert_not_called()

    def test_beacon_end_to_end_with_real_files(self):
        # Exercise the full stack (real fingerprint + real watermark files) across
        # two poll passes: first seeds silently, second fires after a write.
        d = self._make_dir('rules', {'a.rules': 'alert'})
        config = self._config({d: 'suricata'})

        self.assertEqual(rules_beacon.beacon(config), [])  # seed pass
        self.assertEqual(rules_beacon.beacon(config), [])  # unchanged pass

        with open(os.path.join(d, 'b.rules'), 'w') as f:
            f.write('alert tcp any any -> any any')
        self.assertEqual(rules_beacon.beacon(config), [{'tag': 'suricata', 'path': d}])


if __name__ == '__main__':
    unittest.main()
