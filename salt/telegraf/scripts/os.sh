#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    NEEDS_RESTART=0

    if which needs-restarting &> /dev/null; then
        # DNF/RPM family
        if ! needs-restarting -r &> /dev/null; then
            NEEDS_RESTART=1
        fi
    else
        # APT family
        if [ -f /var/run/reboot-required ]; then
            NEEDS_RESTART=1
        fi
    fi

    echo "os restart=$NEEDS_RESTART"

fi

exit 0
