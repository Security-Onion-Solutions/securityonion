#!/bin/bash

# Clone github
mkdir /tmp/sogh
cd /tmp/sogh
git clone https://github.com/TOoSmOotH/securityonion-saltstack.git
cd securityonion-saltstack
rsync -a pillar /opt/so/saltstack/
rsync -a --exclude-from 'exclude-list.txt' salt /opt/so/saltstack/
chown -R socore:socore /opt/so
chmod 755 /opt/so/saltstack/pillar/firewall/addfirewall.sh
cd ~
rm -rf /tmp/sogh
salt-call state.highstate
