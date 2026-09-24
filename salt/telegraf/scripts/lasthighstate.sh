#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    if [ -r "/var/log/salt/lasthighstate" ]; then
        LAST_HIGHSTATE_END=$(date -r /var/log/salt/lasthighstate +%s)
        NOW=$(date +%s)
        HIGHSTATE_AGE_SECONDS=$((NOW-LAST_HIGHSTATE_END))
        echo "salt highstate_age_seconds=$HIGHSTATE_AGE_SECONDS"
    fi

fi

exit 0
