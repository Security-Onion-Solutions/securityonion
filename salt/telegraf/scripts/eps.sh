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

THEGREP=$(ps -ef | grep $0 | grep -v $$ | grep -v grep)

if [ ! "$THEGREP" ]; then

    PREVCOUNTFILE='/tmp/eps.txt'
    EVENTCOUNTCURRENT="$(curl -s localhost:9600/_node/stats | jq '.events.in')"

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

      echo "consumptioneps eps=${EVENTS%%.*}"
    fi
else
    exit 0
fi

