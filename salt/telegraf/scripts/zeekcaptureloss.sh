#!/bin/bash
{% set WORKERS = salt['pillar.get']('sensor:zeek_lbprocs', salt['pillar.get']('sensor:zeek_pins') | length) %}
ZEEKLOG=/host/nsm/zeek/spool/logger/capture_loss.log
if [ -f "$ZEEKLOG" ]; then
  LOSS=$(tail -{{WORKERS}} $ZEEKLOG | awk -F, '{print $NF}' | sed 's/}//' | awk -F: '{LOSS += $2 / {{WORKERS}}} END { print LOSS}')
  echo "zeekcaptureloss loss=$LOSS"
fi
