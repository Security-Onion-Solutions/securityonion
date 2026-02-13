# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# -*- coding: utf-8 -*-

import logging
import os
import time
from datetime import datetime, timedelta
import salt.client

log = logging.getLogger(__name__)

TIMESTAMP_FILE = '/opt/so/state/mav_engine_start_time'

def _get_start_time():
    """Read persisted start time from file, or create one if it doesn't exist."""
    if os.path.exists(TIMESTAMP_FILE):
        with open(TIMESTAMP_FILE, 'r') as f:
            timestamp = f.read().strip()
        start_time = datetime.fromisoformat(timestamp)
        log.info("Loaded existing start time from %s: %s", TIMESTAMP_FILE, start_time)
        return start_time

    start_time = datetime.now()
    with open(TIMESTAMP_FILE, 'w') as f:
        f.write(start_time.isoformat())
    log.info("No existing start time found. Persisted new start time: %s", start_time)
    return start_time


def _clear_start_time():
    """Remove the persisted timestamp file after successful completion."""
    if os.path.exists(TIMESTAMP_FILE):
        os.remove(TIMESTAMP_FILE)
        log.info("Removed timestamp file %s", TIMESTAMP_FILE)


def start(wait_days=7):
    """
    This engine waits for the specified number of days, then changes minimum_auth_version.

    Args:
        wait_days: Days to wait before taking action (default: 7)
    """
    log.info(
        "Starting minimum_auth_version engine - Wait time: %d days",
        wait_days
    )

    start_time = _get_start_time()
    wait_delta = timedelta(days=wait_days)
    mav_removed = False
    caller = salt.client.Caller()

    while True:
        if not mav_removed:
            elapsed = datetime.now() - start_time

            if elapsed >= wait_delta:
                log.info("Changing minimum_auth_version")
                _clear_start_time()
                result = caller.cmd('state.apply', 'salt.master.remove_minimum_auth_version', kwarg={'queue': True})
                # We shouldn't reach this line since the above line should remove the engine and restart salt-master
                log.info("State apply result: %s", result)
                mav_removed = True
            else:
                remaining = wait_delta - elapsed
                days_remaining = remaining.total_seconds() / 86400
                log.info("Time remaining before changing minimum_auth_version: %.1f days", days_remaining)

        time.sleep(3600)  # Check hourly
