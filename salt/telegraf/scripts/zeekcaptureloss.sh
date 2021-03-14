#!/bin/bash
#
# Copyright 2014,2015,2016,2017,2018,2019,2020,2021 Security Onion Solutions, LLC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# This script returns the average of all the workers average capture loss to telegraf / influxdb in influx format include nanosecond precision timestamp

APP=zeekcaploss
lf=/tmp/$APP-pidLockFile
# create empty lock file if none exists
cat /dev/null >> $lf
read lastPID < $lf
# if lastPID is not null and a process with that pid exists , exit
[ ! -z "$lastPID" -a -d /proc/$lastPID ] && exit
echo $$ > $lf

if [ -d "/host/nsm/zeek/spool/logger" ]; then
  WORKERS={{ salt['pillar.get']('sensor:zeek_lbprocs', salt['pillar.get']('sensor:zeek_pins') | length) }}
  ZEEKLOG=/host/nsm/zeek/spool/logger/capture_loss.log
elif [ -d "/host/nsm/zeek/spool/zeeksa" ]; then
  WORKERS=1
  ZEEKLOG=/host/nsm/zeek/spool/zeeksa/capture_loss.log
else
  echo 'Zeek capture_loss.log not found' >/dev/stderr
  exit 2
fi

LASTCAPTURELOSSLOG=/var/log/telegraf/lastcaptureloss.txt
if [ -f "$ZEEKLOG" ]; then
  CURRENTTS=$(tail -1 $ZEEKLOG | jq .ts | sed 's/"//g')
  if [ -f "$LASTCAPTURELOSSLOG" ]; then
    LASTTS=$(cat $LASTCAPTURELOSSLOG)
    if [[ "$LASTTS" != "$CURRENTTS" ]]; then
      LOSS=$(tail -$WORKERS $ZEEKLOG | awk -F, '{print $NF}' | sed 's/}//' | awk -v WORKERS=$WORKERS -F: '{LOSS += $2 / WORKERS} END { print LOSS}')
      echo "zeekcaptureloss loss=$LOSS"
    fi
  fi
  echo "$CURRENTTS" > $LASTCAPTURELOSSLOG
fi
