#!/bin/bash
# This script returns the packets dropped by Zeek, but it isn't a percentage. $LOSS * 100 would be the percentage

APP=zeekloss
lf=/tmp/$APP-pidLockFile
# create empty lock file if none exists
cat /dev/null >> $lf
read lastPID < $lf
# if lastPID is not null and a process with that pid exists , exit
[ ! -z "$lastPID" -a -d /proc/$lastPID ] && exit
echo $$ > $lf

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
