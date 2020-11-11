#!/bin/bash

APP=checkfiles
lf=/tmp/$APP-pidLockFile
# create empty lock file if none exists
cat /dev/null >> $lf
read lastPID < $lf
# if lastPID is not null and a process with that pid exists , exit
[ ! -z "$lastPID" -a -d /proc/$lastPID ] && exit
echo $$ > $lf

FILES=$(ls -1x /host/nsm/faf/complete/ | wc -l)

echo "faffiles files=$FILES"
