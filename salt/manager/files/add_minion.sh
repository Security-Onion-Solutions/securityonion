#!/usr/bin/env bash

# This script adds pillar and schedule files securely
local_salt_dir=/opt/so/saltstack/local
MINION=$1

  echo "Adding $1" 
  cp /tmp/$MINION/pillar/$MINION.sls $local_salt_dir/pillar/minions/
  if [ "$(ls -A /tmp/$MINION/schedules/)" ]; then
    cp /tmp/$MINION/schedules/* $local_salt_dir/salt/patch/os/schedules/
  fi
  rm -rf /tmp/$MINION