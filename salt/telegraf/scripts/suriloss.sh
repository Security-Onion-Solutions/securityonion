#!/bin/bash

SURILOG=$(tac /var/log/suricata/stats.log | grep kernel | head -4)
CHECKIT=$(echo $SURILOG | grep -o 'drop' | wc -l)

if [ $CHECKIT == 2 ]; then
  declare RESULT=($SURILOG)

  CURRENTDROP=${RESULT[4]}
  PASTDROP=${RESULT[14]}
  DROPPED=$(($CURRENTDROP - $PASTDROP))
  if [ $DROPPED == 0 ]; then
    LOSS=0
    echo "suridrop drop=0"
  else
    CURRENTPACKETS=${RESULT[9]}
    PASTPACKETS=${RESULT[19]}
    TOTAL=$(($CURRENTPACKETS - $PASTPACKETS))

    LOSS=$(echo $DROPPED $TOTAL / p | dc)
    echo "suridrop drop=$LOSS"
  fi
else
  echo "suridrop drop=0"
fi
