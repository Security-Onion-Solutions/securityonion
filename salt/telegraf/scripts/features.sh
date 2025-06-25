#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    FPS_ENABLED=$(cat /var/log/sostatus/fps_enabled)
    LKS_ENABLED=$(cat /var/log/sostatus/lks_enabled)

    echo "features fps=$FPS_ENABLED"
    echo "features lks=$LKS_ENABLED"
fi

exit 0
