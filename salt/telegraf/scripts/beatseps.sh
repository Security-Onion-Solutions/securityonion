#!/bin/bash
#
# Copyright 2014,2015,2016,2017,2018,2019,2020,2021 Security Onion Solutions, LLC
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
