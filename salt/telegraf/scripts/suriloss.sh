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

    SURILOG=$(tac /var/log/suricata/stats.log | grep kernel | head -4)
    CHECKIT=$(echo $SURILOG | grep -o 'drop' | wc -l)

    if [ $CHECKIT == 2 ]; then
      declare RESULT=($SURILOG)

      CURRENTDROP=${RESULT[4]}
      PASTDROP=${RESULT[14]}
      DROPPED=$((CURRENTDROP - PASTDROP))
      if [ $DROPPED == 0 ]; then
        LOSS=0
        echo "suridrop drop=0"
      else
        CURRENTPACKETS=${RESULT[9]}
        PASTPACKETS=${RESULT[19]}
        TOTALCURRENT=$((CURRENTPACKETS + CURRENTDROP))
        TOTALPAST=$((PASTPACKETS + PASTDROP))
        TOTAL=$((TOTALCURRENT - TOTALPAST))

        LOSS=$(echo 4 k $DROPPED $TOTAL / p | dc)
        echo "suridrop drop=$LOSS"
      fi
    fi

fi

exit 0
