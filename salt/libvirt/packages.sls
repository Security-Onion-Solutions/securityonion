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
{% if sls.split('.')[0] in allowed_states or sls in allowed_states %}
{%   if 'vrt' in salt['pillar.get']('features', []) %}

# allows for creating vm images
# any node manipulating images needs this
# used on manager for setup_hypervisor runner
install_qemu-img:
  pkg.installed:
    - name: qemu-img

# used on manager for setup_hypervisor runner
install_xorriso:
  pkg.installed:
    - name: xorriso

install_libvirt-libs:
  pkg.installed:
    - name: libvirt-libs

libvirt_python_wheel:
  file.recurse:
    - name: /opt/so/conf/libvirt/source-packages/libvirt-python
    - source: salt://libvirt/source-packages/libvirt-python
    - makedirs: True
    - clean: True

libvirt_python_module:
  cmd.run:
    - name: /opt/saltstack/salt/bin/python3 -m pip install --no-index --find-links=/opt/so/conf/libvirt/source-packages/libvirt-python libvirt-python
    - onchanges:
      - file: libvirt_python_wheel

{%     if 'hype' in grains.id.split('_') | last %}

# provides virsh
install_libvirt-client:
  pkg.installed:
    - name: libvirt-client

install_guestfs-tools:
  pkg.installed:
    - name: guestfs-tools

install_virt-install:
  pkg.installed:
    - name: virt-install

# needed for for so-qcow2-modify-network - import guestfs
install_python3-libguestfs:
  pkg.installed:
    - name: python3-libguestfs
###

{%     endif %}

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
