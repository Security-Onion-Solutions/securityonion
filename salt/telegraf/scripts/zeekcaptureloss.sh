#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# This script returns the average of all the workers average capture loss to telegraf / influxdb in influx format include nanosecond precision timestamp

# if this script isn't already running
{%- from 'zeek/config.map.jinja' import ZEEKMERGED %}
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

    if [ -d "/host/nsm/zeek/spool/logger" ]; then
{%- if ZEEKMERGED.config.node.pins %}
      WORKERS={{ ZEEKMERGED.config.node.pins | length }}
{%- else %}
      WORKERS={{ ZEEKMERGED.config.node.lb_procs }}
{%- endif %}
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

fi

exit 0
