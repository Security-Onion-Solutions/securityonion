#!/bin/bash

APP=stenoloss
lf=/tmp/$APP-pidLockFile
# create empty lock file if none exists
cat /dev/null >> $lf
read lastPID < $lf
# if lastPID is not null and a process with that pid exists , exit
[ ! -z "$lastPID" -a -d /proc/$lastPID ] && exit
echo $$ > $lf

# Get the data
DROP=$(tac /var/log/stenographer/stenographer.log | grep -m1 drop | awk '{print $14}' | awk -F "=" '{print $2}')

echo "stenodrop drop=$DROP"
