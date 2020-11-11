#!/bin/bash

APP=influxsize
lf=/tmp/$APP-pidLockFile
# create empty lock file if none exists
cat /dev/null >> $lf
read lastPID < $lf
# if lastPID is not null and a process with that pid exists , exit
[ ! -z "$lastPID" -a -d /proc/$lastPID ] && exit
echo $$ > $lf

INFLUXSIZE=$(du -s -k /host/nsm/influxdb | awk {'print $1'})

echo "influxsize kbytes=$INFLUXSIZE"
