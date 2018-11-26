#!/usr/bin/env bash

# This script adds sensors/nodes/etc to the nodes tab

TYPE=$1
NAME=$2
IPADDRESS=$3
CPUS=$4
MANINT=$5
MONINT=$6


if grep -q $IPADDRESS "/opt/so/saltstack/pillar/data/$1.sls"; then
  echo "Node Already Present"
else
  echo "  $NAME:" >> /opt/so/saltstack/pillar/data/$1.sls
  echo "    ip: $IPADDRESS" >> /opt/so/saltstack/pillar/data/$1.sls
  echo "    manint: $MANINT" >> /opt/so/saltstack/pillar/data/$1.sls
  echo "    totalcpus: $CPUS"
  if [ $TYPE == 'sensorstab' ]; then
    echo "    monint: $MONINT" >> /opt/so/saltstack/pillar/data/$1.sls
  fi
  if [ $TYPE == 'evaltab' ]; then
    echo "    monint: $MONINT" >> /opt/so/saltstack/pillar/data/$1.sls
  fi

  salt-call state.apply common
  salt-call state.apply utility

fi
