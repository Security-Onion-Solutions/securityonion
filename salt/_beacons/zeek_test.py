# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import unittest
from unittest.mock import MagicMock

import zeek

ZEEKCTL_CMD = "runuser -l zeek -c '/opt/zeek/bin/zeekctl status'"


class TestZeekBeacon(unittest.TestCase):

    def setUp(self):
        # zeek.py relies on the __salt__ dunder that Salt injects at load time.
        # Nothing defines it under test, so we attach a dict of mock loader
        # functions to the module and remove it again afterwards.
        self.salt = {
            'docker.run': MagicMock(return_value='Zeek is running'),
            'healthcheck.is_enabled': MagicMock(return_value=True),
            'telegraf.send': MagicMock(),
        }
        zeek.__salt__ = self.salt
        self.addCleanup(lambda: delattr(zeek, '__salt__'))

    # -- status -----------------------------------------------------------

    def test_status_runs_zeekctl_and_returns_output(self):
        self.salt['docker.run'].return_value = 'Zeek is running'
        result = zeek.status()
        self.assertEqual(result, 'Zeek is running')
        self.salt['docker.run'].assert_called_once_with('so-zeek', ZEEKCTL_CMD)

    # -- beacon -----------------------------------------------------------

    def test_beacon_disabled_returns_empty_and_skips_telegraf(self):
        self.salt['healthcheck.is_enabled'].return_value = False
        self.assertEqual(zeek.beacon({}), [])
        self.salt['telegraf.send'].assert_not_called()

    def test_beacon_running_reports_no_restart(self):
        self.salt['docker.run'].return_value = 'Zeek is running'
        self.assertEqual(zeek.beacon({}), [{'zeek_restart': False}])
        self.salt['telegraf.send'].assert_called_once_with('healthcheck zeek_restart=False')

    def test_beacon_unhealthy_status_triggers_restart(self):
        # Each of these status tokens should flag a restart (the or-chain in beacon).
        for status_text in ('Zeek is stopped', 'Zeek crashed', 'Zeek error state', 'Zeek error:'):
            with self.subTest(status=status_text):
                self.salt['docker.run'].return_value = status_text
                self.salt['telegraf.send'].reset_mock()
                self.assertEqual(zeek.beacon({}), [{'zeek_restart': True}])
                self.salt['telegraf.send'].assert_called_once_with('healthcheck zeek_restart=True')


if __name__ == '__main__':
    unittest.main()
