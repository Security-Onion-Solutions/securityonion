#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.



# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    CONTAINERSLOG=/var/log/somon/containers.log
    # the collector rewrites this every minute; report nothing rather than repeating a stale
    # file as if it were current, in case a run was skipped or the collector is wedged
    MAXAGE=150

    if [ -r "$CONTAINERSLOG" ]; then
        AGE=$(( $(date +%s) - $(stat -c %Y "$CONTAINERSLOG") ))
        if [ "$AGE" -le "$MAXAGE" ]; then
            cat $CONTAINERSLOG
        fi
    fi

    exit 0

fi

exit 0
