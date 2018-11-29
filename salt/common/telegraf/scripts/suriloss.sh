#!/bin/bash

SURILOG=$(tac /var/log/suricata/stats.log | grep kernel | head -4)
CHECKIT=$(echo $SURILOG | grep drop | wc -l)

if [ $CHECKIT == 2 ]; then
  declare RESULT=($SURILOG)

  CURRENTDROP=${RESULT[4]}
  PASTDROP=${RESULT[14]}
  DROPPED=$(($CURRENTDROP - $PASTDROP))

  CURRENTPACKETS=${RESULT[9]}
  PASTPACKETS=${RESULT[19]}
  TOTAL=$(($CURRENTPACKETS - $PASTPACKETS))

  LOSS=$(echo $DROPPED $TOTAL / p | dc)
  echo "suridrop drop=$LOSS"
else
  echo "suridrop drop=0"
fi
