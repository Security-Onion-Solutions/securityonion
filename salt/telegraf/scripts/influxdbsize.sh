#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.



# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    INFLUXLOG=/var/log/telegraf/influxdb_size.log
 
    if [ -f "$INFLUXLOG" ]; then
        INFLUXSTATUS=$(cat $INFLUXLOG)
        echo "influxsize kbytes=$INFLUXSTATUS"
    fi
fi

exit 0
