#!/bin/bash

APP=suriloss
lf=/tmp/$APP-pidLockFile
# create empty lock file if none exists
cat /dev/null >> $lf
read lastPID < $lf
# if lastPID is not null and a process with that pid exists , exit
[ ! -z "$lastPID" -a -d /proc/$lastPID ] && exit
echo $$ > $lf

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
    TOTALCURRENT=$(($CURRENTPACKETS + $CURRENTDROP))
    TOTALPAST=$(($PASTPACKETS + $PASTDROP))
    TOTAL=$(($TOTALCURRENT - $TOTALPAST))

    LOSS=$(echo $DROPPED $TOTAL / p | dc)
    echo "suridrop drop=$LOSS"
  fi
else
  echo "suridrop drop=0"
fi
