#!/bin/bash

APP=redis
lf=/tmp/$APP-pidLockFile
# create empty lock file if none exists
cat /dev/null >> $lf
read lastPID < $lf
# if lastPID is not null and a process with that pid exists , exit
[ ! -z "$lastPID" -a -d /proc/$lastPID ] && exit
echo $$ > $lf

UNPARSED=$(redis-cli llen logstash:unparsed | awk '{print $1}')
PARSED=$(redis-cli llen logstash:parsed | awk '{print $1}')

echo "redisqueue unparsed=$UNPARSED,parsed=$PARSED"
