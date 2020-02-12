#!/bin/bash

# Clone github
mkdir /tmp/sogh
cd /tmp/sogh
#git clone -b dev https://github.com/Security-Onion-Solutions/securityonion-saltstack.git
git clone https://github.com/Security-Onion-Solutions/securityonion-saltstack.git
cd securityonion-saltstack
rsync -a --exclude-from 'exclude-list.txt' salt /opt/so/saltstack/
chown -R socore:socore /opt/so/saltstack/salt
chmod 755 /opt/so/saltstack/pillar/firewall/addfirewall.sh
cd ~
rm -rf /tmp/sogh
# Run so-elastic-download here and call this soup with some magic
salt-call state.highstate
