# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}

# used for qemu+ssh connection between manager and hypervisors
create_soqemussh_user:
  user.present:
    - name: soqemussh
    - shell: /bin/bash
    - home: /home/soqemussh
{% if not GLOBALS.is_manager %}
    - groups:
      - wheel
      - qemu
      - libvirt
{% endif %}

{% if GLOBALS.is_manager %}

create_local_libvirt_ssh_key_dir:
  file.directory:
    - name: /opt/so/saltstack/local/salt/libvirt/ssh/keys
    - user: socore
    - group: socore
    - mode: 755
    - makedirs: True

# generate the key pair and put the pub key in salt local files roots
generate_ssh_key_soqemussh:
  cmd.run:
    - name: ssh-keygen -q -N '' -t ed25519 -f /home/soqemussh/.ssh/id_ed25519
    - runas: soqemussh
    - unless: test -f /home/soqemussh/.ssh/id_ed25519
    - require:
      - user: create_soqemussh_user

soqemussh_ssh_key_to_local:
  cmd.run:
    - name: cp /home/soqemussh/.ssh/id_ed25519.pub /opt/so/saltstack/local/salt/libvirt/ssh/keys
    - onchanges:
      - cmd: generate_ssh_key_soqemussh

qemu_ssh_client_config:
  file.managed:
    - name: /root/.ssh/config
    - source: salt://libvirt/ssh/files/config

{% else %}

soqemussh_pub_key:
  ssh_auth.present:
    - user: soqemussh
    - source: salt://libvirt/ssh/keys/id_ed25519.pub

{% endif %}
