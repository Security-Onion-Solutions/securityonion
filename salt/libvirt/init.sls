# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'libvirt/map.jinja' import LIBVIRTMERGED %}

include:
  - libvirt.packages

install_libvirt:
  pkg.installed:
    - name: libvirt

libvirt_conf_dir:
  file.directory:
    - name: /opt/so/conf/libvirt
    - user: 939
    - group: 939
    - makedirs: True

libvirt_config:
  file.managed:
    - name: /opt/so/conf/libvirt/libvirtd.conf
    - source: salt://libvirt/etc/libvirtd.conf.jinja
    - template: jinja
    - defaults:
        LIBVIRTMERGED: {{ LIBVIRTMERGED }}

# since the libvirtd service looks for the config at /etc/libvirt/libvirtd.conf, and we dont want to manage the service looking in a new location, create this symlink to the managed config 
config_symlink:
  file.symlink:
    - name: /etc/libvirt/libvirtd.conf
    - target: /opt/so/conf/libvirt/libvirtd.conf
    - force: True

libvirt_service:
  service.running:
    - name: libvirtd
    - enable: True
    - watch:
      - file: libvirt_config

# places cacert, clientcert, clientkey, servercert and serverkey
# /etc/pki/CA/cacert.pem
# /etc/pki/libvirt/clientcert.pem and /etc/pki/libvirt/servercert.pem
# /etc/pki/libvirt/private/clientkey.pem and /etc/pki/libvirt/private/serverkey.pem
libvirt_keys:
  virt.keys:
    - name: libvirt_keys

install_qemu:
  pkg.installed:
    - name: qemu-kvm

create_host_bridge:
  virt.network_running:
    - name: host-bridge
    - bridge: br0
    - forward: bridge
    - autostart: True

disable_default_bridge:
  cmd.run:
    - name: virsh net-destroy default && virsh net-autostart default --disable
    - require:
      - pkg: install_libvirt-client

# this should only run during the first highstate after setup. it will transfer connection from mgmt to br0
down_original_mgmt_interface:
  cmd.run:
    - name: "nmcli con down {{ pillar.host.mainint }}"
    - unless:
      - nmcli -f GENERAL.CONNECTION dev show {{ pillar.host.mainint }} | grep bridge-slave-{{ pillar.host.mainint }}
    - order: last


# virtlogd service may not restart following reboot without this
#semanage permissive -a virtlogd_t
