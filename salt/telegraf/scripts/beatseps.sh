#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.



# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

  PREVCOUNTFILE='/tmp/beatseps.txt'
  EVENTCOUNTCURRENT="$(curl -s localhost:5066/stats | jq '.libbeat.output.events.acked')"
  FAILEDEVENTCOUNT="$(curl -s localhost:5066/stats | jq '.libbeat.output.events.failed')"

  if [ ! -z "$EVENTCOUNTCURRENT" ]; then

    if [ -f "$PREVCOUNTFILE" ]; then
      EVENTCOUNTPREVIOUS=`cat $PREVCOUNTFILE`
    else
      echo "${EVENTCOUNTCURRENT}" > $PREVCOUNTFILE
      exit 0
    fi

    echo "${EVENTCOUNTCURRENT}" > $PREVCOUNTFILE
    # the division by 30 is because the agent interval is 30 seconds
    EVENTS=$(((EVENTCOUNTCURRENT - EVENTCOUNTPREVIOUS)/30))
    if [ "$EVENTS" -lt 0 ]; then
      EVENTS=0
    fi

    echo "fbstats eps=${EVENTS%%.*},failed=$FAILEDEVENTCOUNT"
  fi

fi

exit 0
