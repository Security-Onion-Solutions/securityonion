#!/usr/bin/env bash

# This script adds pillar and schedule files securely

MINION=$1

  echo "Adding $1" 
  cp /tmp/$MINION/pillar/$MINION.sls /opt/so/saltstack/pillar/minions/
  cp /tmp/$MINION/schedules/* /opt/so/saltstack/salt/patch/os/schedules/
  rm -rf /tmp/$MINION