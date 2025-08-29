# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
#
# Note: Per the Elastic License 2.0, the second limitation states:
#
#   "You may not move, change, disable, or circumvent the license key functionality
#    in the software, and you may not remove or obscure any functionality in the
#    software that is protected by the license key."

{% from 'sensor/map.jinja' import SENSORMERGED %}

{% if 'vrt' in salt['pillar.get']('features') and salt['grains.get']('salt-cloud', {}) %}

include:
  - sensor.vm.network

{% endif %}

offload_script:
  file.managed:
    - name: /etc/NetworkManager/dispatcher.d/pre-up.d/99-so-checksum-offload-disable
    - source: salt://sensor/files/99-so-checksum-offload-disable
    - mode: 755
    - template: jinja

execute_checksum:
  cmd.run:
    - name: /etc/NetworkManager/dispatcher.d/pre-up.d/99-so-checksum-offload-disable
    - onchanges:
      - file: offload_script

combine_bond_script:
  file.managed:
    - name: /usr/sbin/so-combine-bond
    - source: salt://sensor/tools/sbin_jinja/so-combine-bond
    - mode: 755
    - template: jinja
    - defaults:
         CHANNELS: {{ SENSORMERGED.channels }}

execute_combine_bond:
  cmd.run:
    - name: /usr/sbin/so-combine-bond
    - onlyif:
      - ip link show bond0
