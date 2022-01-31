#!/bin/bash
#
# Copyright 2014-2022 Security Onion Solutions, LLC
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

# This script returns the packets dropped by Zeek, but it isn't a percentage. $LOSS * 100 would be the percentage

# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

  ZEEKLOG=$(tac /host/nsm/zeek/logs/packetloss.log | head -2)
  declare RESULT=($ZEEKLOG)
  CURRENTDROP=${RESULT[3]}
  # zeek likely not running if this is true
  if [[ $CURRENTDROP == "rcvd:" ]]; then
    CURRENTDROP=0
    PASTDROP=0
    DROPPED=0
  else
    PASTDROP=${RESULT[9]}
    DROPPED=$((CURRENTDROP - PASTDROP))
  fi
  if [[ "$DROPPED" -le 0 ]]; then
    LOSS=0
    echo "zeekdrop drop=0"
  else
    CURRENTPACKETS=${RESULT[5]}
    PASTPACKETS=${RESULT[11]}
    TOTAL=$((CURRENTPACKETS - PASTPACKETS))
    LOSS=$(echo 4 k $DROPPED $TOTAL / p | dc)
    echo "zeekdrop drop=$LOSS"
  fi

fi

exit 0
