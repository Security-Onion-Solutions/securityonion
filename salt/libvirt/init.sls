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

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{%   if 'vrt' in salt['pillar.get']('features', []) %}
{%     from 'libvirt/map.jinja' import LIBVIRTMERGED %}
{%     from 'salt/map.jinja' import SYSTEMD_UNIT_FILE %}

include:
  - libvirt.64962
  - libvirt.packages
  - libvirt.ssh.users

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
    - source: salt://libvirt/etc/libvirtd.conf
#    - source: salt://libvirt/etc/libvirtd.conf.jinja
#    - template: jinja
#    - defaults:
#        LIBVIRTMERGED: {{ LIBVIRTMERGED }}

# since the libvirtd service looks for the config at /etc/libvirt/libvirtd.conf, and we dont want to manage the service looking in a new location, create this symlink to the managed config 
config_symlink:
  file.symlink:
    - name: /etc/libvirt/libvirtd.conf
    - target: /opt/so/conf/libvirt/libvirtd.conf
    - force: True
    - user: qemu
    - group: qemu

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

# Disable the default storage pool to avoid conflicts
disable_default_pool:
  cmd.run:
    - name: virsh pool-destroy default && virsh pool-autostart default --disable
    - onlyif: virsh pool-list | grep default
    - require:
      - pkg: install_libvirt-client
      - service: libvirt_service

disable_default_bridge:
  cmd.run:
    - name: virsh net-destroy default && virsh net-autostart default --disable
    - require:
      - pkg: install_libvirt-client
      - service: libvirt_service
    - onlyif:
      - virsh net-list | grep default

{%   else %}
{{sls}}_no_license_detected:
  test.fail_without_changes:
    - name: {{sls}}_no_license_detected
    - comment:
      - "Hypervisor nodes are a feature supported only for customers with a valid license.
      Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com
      for more information about purchasing a license to enable this feature."
{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
