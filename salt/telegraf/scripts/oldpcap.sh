#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.



# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    # Get the data
    OLDPCAP=$(find /host/nsm/pcap -type f -exec stat -c'%n %Z' {} + | sort | grep -v "\." | head -n 1 | awk {'print $2'})
    DATE=$(date +%s)
    AGE=$(($DATE - $OLDPCAP))

    echo "pcapage seconds=$AGE"

fi

exit 0
