#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.




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
