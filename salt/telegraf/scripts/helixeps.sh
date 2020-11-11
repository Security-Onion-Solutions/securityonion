#!/bin/bash

APP=helixeps
lf=/tmp/$APP-pidLockFile
# create empty lock file if none exists
cat /dev/null >> $lf
read lastPID < $lf
# if lastPID is not null and a process with that pid exists , exit
[ ! -z "$lastPID" -a -d /proc/$lastPID ] && exit
echo $$ > $lf

PREVCOUNTFILE='/tmp/helixevents.txt'
EVENTCOUNTCURRENT="$(curl -s localhost:9600/_node/stats | jq '.pipelines.helix.events.out')"

if [ ! -z "$EVENTCOUNTCURRENT" ]; then

  if [ -f "$PREVCOUNTFILE" ]; then
    EVENTCOUNTPREVIOUS=`cat $PREVCOUNTFILE`
  else
    echo "${EVENTCOUNTCURRENT}" > $PREVCOUNTFILE
    exit 0
  fi

  echo "${EVENTCOUNTCURRENT}" > $PREVCOUNTFILE
  EVENTS=$(((EVENTCOUNTCURRENT - EVENTCOUNTPREVIOUS)/30))
  if [ "$EVENTS" -lt 0 ]; then
    EVENTS=0
  fi

  echo "helixeps eps=${EVENTS%%.*}"

fi

exit 0
