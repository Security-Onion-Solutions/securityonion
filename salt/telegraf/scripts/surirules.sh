#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Read Suricata ruleset stats from JSON file written by so-suricata-rulestats cron job
# JSON format: {"rules_loaded":45879,"rules_failed":1,"last_reload":"2025-12-04T14:10:57+0000","return":"OK"}
# or on failure: {"return":"FAIL"}

# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    STATSFILE="/var/log/suricata/rulestats.json"

    # Check file exists, is less than 90 seconds old, and has valid data
    if [ -f "$STATSFILE" ] && [ $(($(date +%s) - $(stat -c %Y "$STATSFILE"))) -lt 90 ] && jq -e '.return == "OK" and .rules_loaded != null and .rules_failed != null' "$STATSFILE" > /dev/null 2>&1; then
        LOADED=$(jq -r '.rules_loaded' "$STATSFILE")
        FAILED=$(jq -r '.rules_failed' "$STATSFILE")
        RELOAD_TIME=$(jq -r '.last_reload // ""' "$STATSFILE")

        echo "surirules loaded=${LOADED}i,failed=${FAILED}i,reload_time=\"${RELOAD_TIME}\",status=\"ok\""
    else
        echo "surirules loaded=0i,failed=0i,reload_time=\"\",status=\"unknown\""
    fi

fi

exit 0
