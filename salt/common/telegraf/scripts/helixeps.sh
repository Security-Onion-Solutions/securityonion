#!/bin/bash

PREVCOUNTFILE='/tmp/helixevents.txt'
EVENTCOUNTCURRENT="$(curl -s localhost:9600/_node/stats | jq '.pipelines.eval.events.out')"

if [ ! -z "$EVENTCOUNTCURRENT" ]; then

  if [ -f "$PREVCOUNTFILE" ]; then
    EVENTCOUNTPREVIOUS=`cat $PREVCOUNTFILE`
  else
    echo "${EVENTCOUNTCURRENT}" > $PREVCOUNTFILE
    exit 0
  fi

  echo "${EVENTCOUNTCURRENT}" > $PREVCOUNTFILE
  EVENTS=$((EVENTCOUNTCURRENT - EVENTCOUNTPREVIOUS))
  if [ "$EVENTS" -lt 0 ]; then
    EVENTS=0
  fi

  echo "helixeps eps=${EVENTS}"

fi

exit 0
