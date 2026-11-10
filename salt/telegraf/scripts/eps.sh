#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.



# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    PREVCOUNTFILE='/tmp/eps.txt'
    STATS="$(curl -s localhost:9600/_node/stats)"

    if echo "$STATS" | jq -e '.pipelines.search' > /dev/null 2>&1; then
      STAGE=search
      COUNT="$(echo "$STATS" | jq '.pipelines.search.events.out')"
    elif echo "$STATS" | jq -e '.pipelines.receiver' > /dev/null 2>&1; then
      STAGE=receiver
      COUNT="$(echo "$STATS" | jq '.pipelines.receiver.events.in')"
    else
      exit 0
    fi

    if ! [[ "$COUNT" =~ ^[0-9]+$ ]]; then
      exit 0
    fi

    NOW=$(date +%s)
    read -r PREVEPOCH PREVCOUNT 2>/dev/null < "$PREVCOUNTFILE"
    echo "${NOW} ${COUNT}" > "$PREVCOUNTFILE"

    if ! [[ "$PREVEPOCH" =~ ^[0-9]+$ && "$PREVCOUNT" =~ ^[0-9]+$ ]]; then
      exit 0
    fi

    ELAPSED=$((NOW - PREVEPOCH))
    DELTA=$((COUNT - PREVCOUNT))
    if [ "$ELAPSED" -le 0 ] || [ "$DELTA" -lt 0 ]; then
      EPS=0
    else
      EPS=$((DELTA / ELAPSED))
    fi

    echo "consumptioneps,stage=${STAGE} eps=${EPS}"

fi

exit 0
