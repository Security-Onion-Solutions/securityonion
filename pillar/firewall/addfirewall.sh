#!/usr/bin/env bash

# This script adds ip addresses to specific rule sets defined by the user

POLICY=$1
IPADDRESS=$2

if grep -q $2 "/opt/so/saltstack/pillar/firewall/$1.sls"; then
  echo "Firewall Rule Already There"
else
  echo "  - $2" >> /opt/so/saltstack/pillar/firewall/$1.sls
  salt-call state.apply firewall queue=True
fi
