#!/bin/bash
# This script returns the average of all the workers average capture loss to telegraf / influxdb in influx format include nanosecond precision timestamp
{%- set WORKERS = salt['pillar.get']('sensor:zeek_lbprocs', salt['pillar.get']('sensor:zeek_pins') | length) %}
ZEEKLOG=/host/nsm/zeek/spool/logger/capture_loss.log
LASTCAPTURELOSSLOG=/host/opt/so/log/telegraf_lastcaptureloss.txt
if [ -f "$ZEEKLOG" ]; then
  CURRENTTS=$(tail -1 $ZEEKLOG | jq .ts | sed 's/"//g')
  if [ -f "$LASTCAPTURELOSSLOG" ]; then
    LASTTS=$(cat $LASTCAPTURELOSSLOG)
    if [[ "$LASTTS" != "$CURRENTTS" ]]; then
      LOSS=$(tail -{{WORKERS}} $ZEEKLOG | awk -F, '{print $NF}' | sed 's/}//' | awk -F: '{LOSS += $2 / {{WORKERS}}} END { print LOSS}')
      echo "zeekcaptureloss loss=$LOSS"
    fi
  fi
  echo "$CURRENTS" > $LASTCAPTURELOSSLOG
fi