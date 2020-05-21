#!/usr/bin/env bash

# This script adds pillar and schedule files securely
default_salt_dir=/opt/so/saltstack/default
MINION=$1

  echo "Adding $1" 
  cp /tmp/$MINION/pillar/$MINION.sls $default_salt_dir/pillar/minions/
  cp /tmp/$MINION/schedules/* $default_salt_dir/salt/patch/os/schedules/
  rm -rf /tmp/$MINION