#!/bin/bash
ZEEKLOG=$(tac /host/nsm/zeek/logs/packetloss.log | head -2)
declare RESULT=($ZEEKLOG)
CURRENTDROP=${RESULT[3]}
PASTDROP=${RESULT[9]}
DROPPED=$((CURRENTDROP - PASTDROP))
if [ $DROPPED == 0 ]; then
  LOSS=0
  echo "zeekdrop drop=0"
else
  CURRENTPACKETS=${RESULT[5]}
  PASTPACKETS=${RESULT[11]}
  TOTAL=$((CURRENTPACKETS - PASTPACKETS))
  LOSS=$(echo $DROPPED $TOTAL / p | dc)
  echo "zeekdrop drop=$LOSS"
fi