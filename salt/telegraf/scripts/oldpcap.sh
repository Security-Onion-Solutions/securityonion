#!/bin/bash

APP=oldpcap
lf=/tmp/$APP-pidLockFile
# create empty lock file if none exists
cat /dev/null >> $lf
read lastPID < $lf
# if lastPID is not null and a process with that pid exists , exit
[ ! -z "$lastPID" -a -d /proc/$lastPID ] && exit
echo $$ > $lf

# Get the data
OLDPCAP=$(find /host/nsm/pcap -type f -exec stat -c'%n %Z' {} + | sort | grep -v "\." | head -n 1 | awk {'print $2'})
DATE=$(date +%s)
AGE=$(($DATE - $OLDPCAP))

echo "pcapage seconds=$AGE"
