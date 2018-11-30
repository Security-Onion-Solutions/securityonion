#!/bin/bash

BROLOG=$(tac /host/nsm/bro/logs/packetloss.log | head -2)
declare RESULT=($BROLOG)
CURRENTDROP=${RESULT[3]}
PASTDROP=${RESULT[9]}
DROPPED=$(($CURRENTDROP - $PASTDROP))
if [ $DROPPED == 0 ]; then
  LOSS=0
  echo "brodrop drop=0"
else
  CURRENTPACKETS=${RESULT[5]}
  PASTPACKETS=${RESULT[11]}
  TOTAL=$(($CURRENTPACKETS - $PASTPACKETS))
  LOSS=$(echo $DROPPED $TOTAL / p | dc)
  echo "brodrop drop=$LOSS"
fi
