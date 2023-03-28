#!/bin/bash
#
# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.



# This script returns the packets dropped by Zeek, but it isn't a percentage. $LOSS * 100 would be the percentage

# if this script isn't already running
if [[ ! "`pidof -x $(basename $0) -o %PPID`" ]]; then

  ZEEKLOG=$(tac /host/nsm/zeek/logs/packetloss.log | head -2)
  declare RESULT=($ZEEKLOG)
  CURRENTDROP=${RESULT[3]}
  # zeek likely not running if this is true
  if [[ $CURRENTDROP == "rcvd:" ]]; then
    CURRENTDROP=0
    PASTDROP=0
    DROPPED=0
  else
    PASTDROP=${RESULT[9]}
    DROPPED=$((CURRENTDROP - PASTDROP))
  fi
  if [[ "$DROPPED" -le 0 ]]; then
    LOSS=0
    echo "zeekdrop drop=0"
  else
    CURRENTPACKETS=${RESULT[5]}
    PASTPACKETS=${RESULT[11]}
    TOTAL=$((CURRENTPACKETS - PASTPACKETS))
    LOSS=$(echo 4 k $DROPPED $TOTAL / p | dc)
    echo "zeekdrop drop=$LOSS"
  fi

fi

exit 0
