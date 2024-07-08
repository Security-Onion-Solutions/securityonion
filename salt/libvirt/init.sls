# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'libvirt/map.jinja' import LIBVIRTMERGED %}

install_libvirt:
  pkg.installed:
    - name: libvirt

libvirt_config:
  file.managed:
    - name: /etc/libvirt/libvirtd.conf
    - source: salt://libvirt/etc/libvirtd.conf.jinja
    - template: jinja
    - defaults:
        LIBVIRTMERGED: {{ LIBVIRTMERGED }}

libvirt_service:
  service.running:
    - name: libvirtd

libvirt_conf_dir:
  file.directory:
    - name: /opt/so/conf/libvirt
    - user: 939
    - group: 939
    - makedirs: True

libvirt_source-packages_dir:
  file.directory:
    - name: /opt/so/conf/libvirt/source-packages

libvirt_python_wheel:
  file.recurse:
    - name: /opt/so/conf/libvirt/source-packages/libvirt-python
    - source: salt://libvirt/source-packages/libvirt-python
    - clean: True

libvirt_python_module:
  cmd.run:
    - name: /opt/saltstack/salt/bin/python3.10 -m pip install --no-index --find-links=/opt/so/conf/libvirt/source-packages/libvirt-python libvirt-python
    - onchanges:
      - file: libvirt_python_wheel

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

install_libguestfs:
  pkg.installed:
    - name: libguestfs

# required for the network states below
install_NetworkManager-updown:
  pkg.installed:
    - name: NetworkManager-initscripts-updown

ens18:
  network.managed:
    - enabled: True
    - type: eth
    - bridge: virbr0

virbr0:
  network.managed:
    - enabled: True
    - type: bridge
    - proto: dhcp
    - require:
      - network: ens18
