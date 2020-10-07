#!/bin/bash
# This script returns the average of all the workers average capture loss to telegraf / influxdb in influx format include nanosecond precision timestamp
{%- set WORKERS = salt['pillar.get']('sensor:zeek_lbprocs', salt['pillar.get']('sensor:zeek_pins') | length) %}
ZEEKLOG=/host/nsm/zeek/spool/logger/capture_loss.log
if [ -f "$ZEEKLOG" ]; then
  LOSS=$(tail -{{WORKERS}} $ZEEKLOG | awk -F, '{print $NF}' | sed 's/}//' | awk -F: '{LOSS += $2 / {{WORKERS}}} END { print LOSS}')
  TS=$(tail -1 $ZEEKLOG | jq .ts | sed 's/"//g')
  TSNANO=$(echo "$(date -d "$TS" +"%s.%N") 1000000000 * p" | dc | awk -F. {'print $1'})
  echo "zeekcaptureloss loss=$LOSS $TSNANO"
fi