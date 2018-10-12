#!/usr/bin/env bash

# This script adds sensors/nodes/etc to the nodes tab

TYPE=$1
NAME=$2
IPADDRESS=$3

if grep -q $IPADDRESS "/opt/so/saltstack/pillar/data/$TYPE.sls"; then
  echo "Storage Node Already in There"
else
  echo "  $NAME:" >> /opt/so/saltstack/pillar/data/$NAME.sls
  echo "    ip: $IPADDRESS" >> /opt/so/saltstack/pillar/data/$NAME.sls

fi
