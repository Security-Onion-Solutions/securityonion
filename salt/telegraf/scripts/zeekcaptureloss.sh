#!/bin/bash
{% set WORKERS = salt['pillar.get']('sensor:zeekprocs', salt['pillar.get']('sensor:zeekpins') | length) %}
ZEEKLOG=/host/nsm/zeek/logs/current/capture_loss.log
if [ -f "$ZEEKLOG" ]; then
  LOSS=$(tail -{{WORKERS}} $ZEEKLOG | awk -F, '{print $NF}' | sed 's/}//' | awk -F: '{LOSS += $2 / {{WORKERS}}} END { print "loss: " LOSS}')
  echo "zeekcaptureloss loss=$LOSS"
fi
