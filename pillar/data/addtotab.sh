#!/usr/bin/env bash

# This script adds sensors/nodes/etc to the nodes tab

TYPE=$1
NAME=$2
IPADDRESS=$3

if grep -q $IPADDRESS "/opt/so/saltstack/pillar/data/$1.sls"; then
  echo "Node Already Present"
else
  echo "  $NAME:" >> /opt/so/saltstack/pillar/data/$1.sls
  echo "    ip: $IPADDRESS" >> /opt/so/saltstack/pillar/data/$1.sls
  salt-call state.apply utility

fi
