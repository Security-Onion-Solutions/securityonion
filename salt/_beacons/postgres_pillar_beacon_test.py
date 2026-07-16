# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import postgres_pillar_beacon


class TestPostgresPillarBeacon(unittest.TestCase):

    def setUp(self):
        # Point WATERMARK_FILE at a throwaway dir so the real read/write helpers
        # (and their os.makedirs/os.rename) run against actual files, then clean
        # it all up in tearDown.
        self.tmpdir = tempfile.mkdtemp()
        self.watermark = os.path.join(self.tmpdir, 'state', 'watch.id')
        patcher = patch.object(postgres_pillar_beacon, 'WATERMARK_FILE', self.watermark)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- trivial contract -------------------------------------------------

    def test_virtual_returns_true(self):
        self.assertTrue(postgres_pillar_beacon.__virtual__())

    def test_validate_returns_valid(self):
        self.assertEqual(postgres_pillar_beacon.validate({}), (True, 'valid'))

    # -- _read_watermark --------------------------------------------------

    def test_read_watermark_valid(self):
        postgres_pillar_beacon._write_watermark(42)
        self.assertEqual(postgres_pillar_beacon._read_watermark(), 42)

    def test_read_watermark_missing_file_returns_none(self):
        # tmp watermark file was never created
        self.assertIsNone(postgres_pillar_beacon._read_watermark())

    def test_read_watermark_garbage_returns_none(self):
        os.makedirs(os.path.dirname(self.watermark), exist_ok=True)
        with open(self.watermark, 'w') as f:
            f.write('nope')
        self.assertIsNone(postgres_pillar_beacon._read_watermark())

    # -- _write_watermark -------------------------------------------------

    def test_write_watermark_round_trip(self):
        postgres_pillar_beacon._write_watermark(7)
        with open(self.watermark) as f:
            self.assertEqual(f.read(), '7')

    def test_write_watermark_swallows_oserror(self):
        with patch.object(postgres_pillar_beacon.os, 'makedirs', side_effect=OSError):
            # Must not raise; failure is logged and the beacon retries next pass.
            postgres_pillar_beacon._write_watermark(5)
        self.assertFalse(os.path.exists(self.watermark))

    # -- _query -----------------------------------------------------------

    def test_query_success_returns_stdout_and_builds_argv(self):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout='rows', stderr='')
        with patch.object(postgres_pillar_beacon.subprocess, 'run', return_value=completed) as mock_run:
            result = postgres_pillar_beacon._query('SELECT 1;')
        self.assertEqual(result, 'rows')
        argv = mock_run.call_args[0][0]
        self.assertEqual(argv[:5], ['docker', 'exec', 'so-postgres', 'psql', '-U'])
        self.assertIn('SELECT 1;', argv)
        self.assertFalse(mock_run.call_args[1].get('shell', False))

    def test_query_timeout_returns_none(self):
        with patch.object(postgres_pillar_beacon.subprocess, 'run',
                          side_effect=subprocess.TimeoutExpired(cmd='psql', timeout=30)):
            self.assertIsNone(postgres_pillar_beacon._query('SELECT 1;'))

    def test_query_generic_exception_returns_none(self):
        with patch.object(postgres_pillar_beacon.subprocess, 'run', side_effect=Exception('boom')):
            self.assertIsNone(postgres_pillar_beacon._query('SELECT 1;'))

    def test_query_nonzero_returncode_returns_none(self):
        completed = subprocess.CompletedProcess(args=[], returncode=1, stdout='', stderr='bad')
        with patch.object(postgres_pillar_beacon.subprocess, 'run', return_value=completed):
            self.assertIsNone(postgres_pillar_beacon._query('SELECT 1;'))

    # -- beacon: first run / seeding --------------------------------------

    def test_beacon_seeds_when_postgres_not_ready(self):
        with patch.object(postgres_pillar_beacon, '_read_watermark', return_value=None), \
             patch.object(postgres_pillar_beacon, '_query', return_value=None), \
             patch.object(postgres_pillar_beacon, '_write_watermark') as mock_write:
            self.assertEqual(postgres_pillar_beacon.beacon({}), [])
        mock_write.assert_not_called()

    def test_beacon_seeds_to_max_id_and_emits_nothing(self):
        with patch.object(postgres_pillar_beacon, '_read_watermark', return_value=None), \
             patch.object(postgres_pillar_beacon, '_query', return_value='7\n'), \
             patch.object(postgres_pillar_beacon, '_write_watermark') as mock_write:
            self.assertEqual(postgres_pillar_beacon.beacon({}), [])
        mock_write.assert_called_once_with(7)

    def test_beacon_seed_unparseable_is_swallowed(self):
        with patch.object(postgres_pillar_beacon, '_read_watermark', return_value=None), \
             patch.object(postgres_pillar_beacon, '_query', return_value='abc'), \
             patch.object(postgres_pillar_beacon, '_write_watermark') as mock_write:
            self.assertEqual(postgres_pillar_beacon.beacon({}), [])
        mock_write.assert_not_called()

    # -- beacon: steady state ---------------------------------------------

    def test_beacon_query_failure_returns_empty(self):
        with patch.object(postgres_pillar_beacon, '_read_watermark', return_value=10), \
             patch.object(postgres_pillar_beacon, '_query', return_value=None), \
             patch.object(postgres_pillar_beacon, '_write_watermark') as mock_write:
            self.assertEqual(postgres_pillar_beacon.beacon({}), [])
        mock_write.assert_not_called()

    def test_beacon_emits_events_and_advances_watermark(self):
        sep = postgres_pillar_beacon.FIELD_SEP
        rows = '11%s5%snode1\n12%s6%s\n' % (sep, sep, sep, sep)
        with patch.object(postgres_pillar_beacon, '_read_watermark', return_value=10), \
             patch.object(postgres_pillar_beacon, '_query', return_value=rows), \
             patch.object(postgres_pillar_beacon, '_write_watermark') as mock_write:
            result = postgres_pillar_beacon.beacon({})
        self.assertEqual(result, [
            {'tag': 'audit_settings', 'id': 11, 'setting_id': '5', 'node_id': 'node1'},
            {'tag': 'audit_settings', 'id': 12, 'setting_id': '6', 'node_id': ''},
        ])
        mock_write.assert_called_once_with(12)

    def test_beacon_skips_malformed_blank_and_noninteger_rows(self):
        sep = postgres_pillar_beacon.FIELD_SEP
        rows = (
            '\n'                       # blank line -> skipped
            '13%s7\n'                  # too few fields -> skipped
            'abc%s8%snodeX\n'          # non-integer id -> skipped
            '14%s9%snodeY\n'           # the one good row
        ) % (sep, sep, sep, sep, sep)
        with patch.object(postgres_pillar_beacon, '_read_watermark', return_value=10), \
             patch.object(postgres_pillar_beacon, '_query', return_value=rows), \
             patch.object(postgres_pillar_beacon, '_write_watermark') as mock_write:
            result = postgres_pillar_beacon.beacon({})
        self.assertEqual(result, [
            {'tag': 'audit_settings', 'id': 14, 'setting_id': '9', 'node_id': 'nodeY'},
        ])
        mock_write.assert_called_once_with(14)

    def test_beacon_no_new_rows_does_not_advance_watermark(self):
        with patch.object(postgres_pillar_beacon, '_read_watermark', return_value=10), \
             patch.object(postgres_pillar_beacon, '_query', return_value=''), \
             patch.object(postgres_pillar_beacon, '_write_watermark') as mock_write:
            self.assertEqual(postgres_pillar_beacon.beacon({}), [])
        mock_write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
