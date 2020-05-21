#!/usr/bin/env bash

# This script adds ip addresses to specific rule sets defined by the user
default_salt_dir=/opt/so/saltstack/default
POLICY=$1
IPADDRESS=$2

if grep -q $2 "$default_salt_dir/pillar/firewall/$1.sls"; then
  echo "Firewall Rule Already There"
else
  echo "  - $2" >> $default_salt_dir/pillar/firewall/$1.sls
  salt-call state.apply firewall queue=True
fi
