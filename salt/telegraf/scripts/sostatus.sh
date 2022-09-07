#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.



# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    SOSTATUSLOG=/var/log/sostatus/status.log
    SOSTATUSSTATUS=$(cat /var/log/sostatus/status.log)

    if [ -f "$SOSTATUSLOG" ]; then
        echo "sostatus status=$SOSTATUSSTATUS"
    else
        exit 0
    fi

fi

exit 0
