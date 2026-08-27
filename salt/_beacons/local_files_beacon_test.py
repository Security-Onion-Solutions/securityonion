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

import local_files_beacon


class TestRulesBeacon(unittest.TestCase):

    def setUp(self):
        # Isolate all on-disk state (watermarks and the dirs we fingerprint) in a
        # throwaway tree, and point WATERMARK_DIR at it so the real read/write
        # helpers run against actual files.
        self.tmpdir = tempfile.mkdtemp()
        self.state = os.path.join(self.tmpdir, 'state')
        patcher = patch.object(local_files_beacon, 'WATERMARK_DIR', self.state)
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
        self.assertTrue(local_files_beacon.__virtual__())

    def test_validate_returns_valid(self):
        self.assertEqual(local_files_beacon.validate({}), (True, 'valid'))

    # -- _paths_from_config -----------------------------------------------

    def test_paths_from_config_list_of_dicts(self):
        config = [{'interval': 10}, {'paths': {'/a': 'suricata', '/b': 'strelka'}}]
        self.assertEqual(
            local_files_beacon._paths_from_config(config),
            {'/a': 'suricata', '/b': 'strelka'},
        )

    def test_paths_from_config_plain_dict(self):
        self.assertEqual(
            local_files_beacon._paths_from_config({'paths': {'/a': 'suricata'}}),
            {'/a': 'suricata'},
        )

    def test_paths_from_config_skips_non_dict_items(self):
        self.assertEqual(local_files_beacon._paths_from_config(['bogus', 42]), {})

    def test_paths_from_config_paths_not_a_dict(self):
        self.assertEqual(local_files_beacon._paths_from_config({'paths': 'nope'}), {})

    def test_paths_from_config_unexpected_type(self):
        self.assertEqual(local_files_beacon._paths_from_config('nonsense'), {})

    # -- _excluded --------------------------------------------------------

    def test_excluded_matches_temp_and_editor_files(self):
        for pathname in ('/rules/foo.swp', '/rules/foo~', '/rules/4913', '/rules/.#foo'):
            self.assertTrue(local_files_beacon._excluded(pathname), pathname)

    def test_excluded_allows_real_rule_files(self):
        self.assertFalse(local_files_beacon._excluded('/rules/suricata.rules'))

    # -- _fingerprint -----------------------------------------------------

    def test_fingerprint_missing_dir_is_empty_tree_digest(self):
        missing = os.path.join(self.tmpdir, 'does-not-exist')
        self.assertEqual(local_files_beacon._fingerprint(missing), hashlib.sha1().hexdigest())

    def test_fingerprint_changes_when_content_changes(self):
        d = self._make_dir('rules', {'a.rules': 'alert'})
        before = local_files_beacon._fingerprint(d)
        with open(os.path.join(d, 'a.rules'), 'w') as f:
            f.write('alert tcp any any -> any any')  # different size
        self.assertNotEqual(local_files_beacon._fingerprint(d), before)

    def test_fingerprint_ignores_excluded_files(self):
        d = self._make_dir('rules', {'a.rules': 'alert'})
        before = local_files_beacon._fingerprint(d)
        with open(os.path.join(d, 'a.rules.swp'), 'w') as f:
            f.write('editor swap')
        self.assertEqual(local_files_beacon._fingerprint(d), before)

    def test_fingerprint_skips_unstatable_entries(self):
        # A dangling symlink appears in os.walk's file list but os.stat raises
        # OSError, exercising the except-continue path.
        d = self._make_dir('rules', {'a.rules': 'alert'})
        good = local_files_beacon._fingerprint(d)
        os.symlink(os.path.join(d, 'missing-target'), os.path.join(d, 'broken.link'))
        self.assertEqual(local_files_beacon._fingerprint(d), good)

    def test_fingerprint_prunes_git_metadata(self):
        # zkg packages are git clones, so the watched tree carries .git.
        d = self._make_dir('zkg', {'pkg.zeek': 'print 1;'})
        before = local_files_beacon._fingerprint(d)
        git_dir = os.path.join(d, 'pkg', '.git', 'refs', 'heads')
        os.makedirs(git_dir)
        with open(os.path.join(git_dir, 'main'), 'w') as f:
            f.write('0' * 40)
        self.assertEqual(local_files_beacon._fingerprint(d), before)

    def test_fingerprint_still_sees_worktree_next_to_git(self):
        d = self._make_dir('zkg', {'pkg.zeek': 'print 1;'})
        os.makedirs(os.path.join(d, 'pkg', '.git'))
        before = local_files_beacon._fingerprint(d)
        with open(os.path.join(d, 'pkg', 'scripts.zeek'), 'w') as f:
            f.write('print 2;')
        self.assertNotEqual(local_files_beacon._fingerprint(d), before)

    # -- _read_watermark / _write_watermark -------------------------------

    def test_watermark_round_trip(self):
        local_files_beacon._write_watermark('suricata', '/rules/suricata', 'deadbeef')
        self.assertEqual(
            local_files_beacon._read_watermark('suricata', '/rules/suricata'), 'deadbeef')

    def test_read_watermark_missing_returns_none(self):
        self.assertIsNone(local_files_beacon._read_watermark('suricata', '/rules/suricata'))

    def test_read_watermark_empty_file_returns_none(self):
        os.makedirs(self.state, exist_ok=True)
        with open(local_files_beacon._watermark_file('suricata', '/rules/suricata'), 'w') as f:
            f.write('')
        self.assertIsNone(local_files_beacon._read_watermark('suricata', '/rules/suricata'))

    def test_write_watermark_swallows_oserror(self):
        with patch.object(local_files_beacon.os, 'makedirs', side_effect=OSError):
            local_files_beacon._write_watermark('suricata', '/rules/suricata', 'deadbeef')
        self.assertIsNone(local_files_beacon._read_watermark('suricata', '/rules/suricata'))

    def test_watermark_file_differs_per_directory_within_one_tag(self):
        # zeek/policy and zeek/zkg share the tag 'zeek'.
        self.assertNotEqual(
            local_files_beacon._watermark_file('zeek', '/local/zeek/policy'),
            local_files_beacon._watermark_file('zeek', '/local/zeek/zkg'),
        )

    def test_watermarks_are_independent_within_one_tag(self):
        local_files_beacon._write_watermark('zeek', '/local/zeek/policy', 'policyhash')
        local_files_beacon._write_watermark('zeek', '/local/zeek/zkg', 'zkghash')
        self.assertEqual(
            local_files_beacon._read_watermark('zeek', '/local/zeek/policy'), 'policyhash')
        self.assertEqual(
            local_files_beacon._read_watermark('zeek', '/local/zeek/zkg'), 'zkghash')

    # -- beacon -----------------------------------------------------------

    def _config(self, mapping):
        return [{'paths': mapping}]

    def test_beacon_seeds_first_run_and_emits_nothing(self):
        with patch.object(local_files_beacon, '_fingerprint', return_value='hash1'), \
             patch.object(local_files_beacon, '_read_watermark', return_value=None), \
             patch.object(local_files_beacon, '_write_watermark') as mock_write:
            result = local_files_beacon.beacon(self._config({'/rules/suricata': 'suricata'}))
        self.assertEqual(result, [])
        mock_write.assert_called_once_with('suricata', '/rules/suricata', 'hash1')

    def test_beacon_emits_on_change(self):
        with patch.object(local_files_beacon, '_fingerprint', return_value='newhash'), \
             patch.object(local_files_beacon, '_read_watermark', return_value='oldhash'), \
             patch.object(local_files_beacon, '_write_watermark') as mock_write:
            result = local_files_beacon.beacon(self._config({'/rules/suricata': 'suricata'}))
        self.assertEqual(result, [{'tag': 'suricata', 'path': '/rules/suricata'}])
        mock_write.assert_called_once_with('suricata', '/rules/suricata', 'newhash')

    def test_beacon_no_change_emits_nothing(self):
        with patch.object(local_files_beacon, '_fingerprint', return_value='samehash'), \
             patch.object(local_files_beacon, '_read_watermark', return_value='samehash'), \
             patch.object(local_files_beacon, '_write_watermark') as mock_write:
            result = local_files_beacon.beacon(self._config({'/rules/suricata': 'suricata'}))
        self.assertEqual(result, [])
        mock_write.assert_not_called()

    def test_beacon_end_to_end_with_real_files(self):
        # Exercise the full stack (real fingerprint + real watermark files) across
        # two poll passes: first seeds silently, second fires after a write.
        d = self._make_dir('rules', {'a.rules': 'alert'})
        config = self._config({d: 'suricata'})

        self.assertEqual(local_files_beacon.beacon(config), [])  # seed pass
        self.assertEqual(local_files_beacon.beacon(config), [])  # unchanged pass

        with open(os.path.join(d, 'b.rules'), 'w') as f:
            f.write('alert tcp any any -> any any')
        self.assertEqual(local_files_beacon.beacon(config), [{'tag': 'suricata', 'path': d}])

    def test_beacon_two_dirs_one_tag_do_not_flap(self):
        # Tag-keyed watermarks would clobber each other and emit on every pass.
        policy = self._make_dir('zeek/policy', {'intel.dat': '#fields\tindicator'})
        zkg = self._make_dir('zeek/zkg', {'README': 'place packages here'})
        config = self._config({policy: 'zeek', zkg: 'zeek'})

        self.assertEqual(local_files_beacon.beacon(config), [])  # seed pass
        self.assertEqual(local_files_beacon.beacon(config), [])  # idle
        self.assertEqual(local_files_beacon.beacon(config), [])  # still idle

        with open(os.path.join(policy, 'intel.dat'), 'a') as f:
            f.write('\nevil.com\tIntel::DOMAIN\tsource\n')
        self.assertEqual(local_files_beacon.beacon(config), [{'tag': 'zeek', 'path': policy}])
        self.assertEqual(local_files_beacon.beacon(config), [])  # quiet again


if __name__ == '__main__':
    unittest.main()
