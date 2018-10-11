#!/usr/bin/env bash

# This script adds sensors/nodes/etc to the nodes tab

TYPE=$1
NAME=$2
IPADDRESS=$3

if grep -q $3 "/opt/so/saltstack/pillar/data/$1.sls"; then
  echo "Storage Node Already in There"
else
  echo "  $2:" >> /opt/so/saltstack/pillar/data/$1.sls
  echo "    - $3" >> /opt/so/saltstack/pillar/data/$1.sls

fi
