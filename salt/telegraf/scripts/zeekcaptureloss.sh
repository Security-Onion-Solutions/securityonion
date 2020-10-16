#!/bin/bash
# This script returns the average of all the workers average capture loss to telegraf / influxdb in influx format include nanosecond precision timestamp

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