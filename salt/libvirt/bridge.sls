# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{%  from 'libvirt/map.jinja' import LIBVIRTMERGED %}
{%  from 'salt/map.jinja' import SYSTEMD_UNIT_FILE %}

down_original_mgmt_interface:
  cmd.run:
    - name: "nmcli con down {{ pillar.host.mainint }}"
    - unless:
      - nmcli -f GENERAL.CONNECTION dev show {{ pillar.host.mainint }} | grep bridge-slave-{{ pillar.host.mainint }}
    - order: last

wait_for_br0_ip:
  cmd.run:
    - name: |
        counter=0
        until ip addr show br0 | grep -q "inet "; do
          sleep 1
          counter=$((counter+1))
          if [ $counter -ge 90 ]; then
            echo "Timeout waiting for br0 to get an IP address"
            exit 1
          fi
        done
        echo "br0 has IP address: $(ip addr show br0 | grep 'inet ' | awk '{print $2}')"
    - timeout: 95
    - onchanges:
      - cmd: down_original_mgmt_interface

update_mine_functions:
  file.managed:
    - name: /etc/salt/minion.d/mine_functions.conf
    - contents: |
        mine_interval: 25
        mine_functions:
          network.ip_addrs:
            - interface: br0
    - onchanges:
      - cmd: wait_for_br0_ip

restart_salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True
    - listen:
      - file: update_mine_functions
