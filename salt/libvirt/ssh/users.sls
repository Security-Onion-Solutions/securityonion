# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}



{% if GLOBALS.is_manager %}

qemu_ssh_client_config:
  file.managed:
    - name: /root/.ssh/config
    - source: salt://libvirt/ssh/files/config

{% else %}

# used for qemu+ssh connection between manager and hypervisors
create_soqemussh_user:
  user.present:
    - name: soqemussh
    - shell: /bin/bash
    - home: /home/soqemussh
    - groups:
      - wheel
      - qemu
      - libvirt

soqemussh_pub_key:
  ssh_auth.present:
    - user: soqemussh
    - source: salt://libvirt/ssh/keys/id_ed25519.pub

{% endif %}
