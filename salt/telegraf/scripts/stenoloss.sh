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

    CHECKIT=$(grep "Thread 0" /var/log/stenographer/stenographer.log |tac |head -2|wc -l)
    STENOGREP=$(grep "Thread 0" /var/log/stenographer/stenographer.log |tac |head -2)

    declare RESULT=($STENOGREP)

    CURRENT_PACKETS=$(echo ${RESULT[9]} | awk -F'=' '{print $2 }')
    CURRENT_DROPS=$(echo ${RESULT[12]} | awk -F'=' '{print $2 }')
    PREVIOUS_PACKETS=$(echo ${RESULT[23]} | awk -F'=' '{print $2 }')
    PREVIOUS_DROPS=$(echo ${RESULT[26]} | awk -F'=' '{print $2 }')

    DROPPED=$((CURRENT_DROPS - PREVIOUS_DROPS))
    TOTAL_CURRENT=$((CURRENT_PACKETS + CURRENT_DROPS))
    TOTAL_PAST=$((PREVIOUS_PACKETS + PREVIOUS_DROPS))
    TOTAL=$((TOTAL_CURRENT - TOTAL_PAST))

    if [ $CHECKIT == 2 ]; then
      if [ $DROPPED == 0 ]; then
        echo "stenodrop drop=$DROPPED"
      else
        LOSS=$(echo "4 k $DROPPED $TOTAL / 100 * p" | dc)
        echo "stenodrop drop=$LOSS"
      fi
    fi
    
else
    exit 0
fi