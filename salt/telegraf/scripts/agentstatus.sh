#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.



# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    LOGFILE=/var/log/agents/agentstatus.log

    # Check to see if the file is there yet so we don't break install verification since there is a 5 minute delay for this file to show up
    if [ -f $LOGFILE ]; then
        ONLINE=$(cat $LOGFILE | grep -wF online | awk '{print $2}' | tr -d ',')
        ERROR=$(cat $LOGFILE | grep -wF error | awk '{print $2}' | tr -d ',')
        INACTIVE=$(cat $LOGFILE | grep -wF inactive | awk '{print $2}' | tr -d ',')
        OFFLINE=$(cat $LOGFILE | grep -wF offline | awk '{print $2}' | tr -d ',')
        UPDATING=$(cat $LOGFILE | grep -wF updating | awk '{print $2}' | tr -d ',')
        UNENROLLED=$(cat $LOGFILE | grep -wF unenrolled | awk '{print $2}' | tr -d ',')
        OTHER=$(cat $LOGFILE | grep -wF other | awk '{print $2}' | tr -d ',')
        EVENTS=$(cat $LOGFILE | grep -wF events | awk '{print $2}' | tr -d ',')
        TOTAL=$(cat $LOGFILE | grep -wF total | awk '{print $2}' | tr -d ',')
        ALL=$(cat $LOGFILE | grep -wF all | awk '{print $2}' | tr -d ',')
        ACTIVE=$(cat $LOGFILE | grep -wF active | awk '{print $2}')

        echo "agentstatus online=$ONLINE,error=$ERROR,inactive=$INACTIVE,offline=$OFFLINE,updating=$UPDATING,unenrolled=$UNENROLLED,other=$OTHER,events=$EVENTS,total=$TOTAL,all=$ALL,active=$ACTIVE"
    fi
    
fi

exit 0
