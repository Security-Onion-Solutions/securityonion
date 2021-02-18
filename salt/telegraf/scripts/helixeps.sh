#!/bin/bash
#
# Copyright 2014,2015,2016,2017,2018,2019,2020 Security Onion Solutions, LLC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
