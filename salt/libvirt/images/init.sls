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
{%   if 'hvn' in salt['pillar.get']('features', []) %}

include:
  - libvirt.packages

# Copy base image files
baseimagefiles_sool9:
  file.recurse:
    - name: /nsm/libvirt/images/sool9/
    - source: salt://libvirt/images/sool9/
    - makedirs: True

# Define the storage pool
define_storage_pool_sool9:
  virt.pool_defined:
    - name: sool9
    - ptype: dir
    - target: /nsm/libvirt/images/sool9
    - require:
      - file: baseimagefiles_sool9
      - cmd: libvirt_python_module

# Start the storage pool
start_storage_pool_sool9:
  virt.pool_running:
    - name: sool9
    - ptype: dir
    - target: /nsm/libvirt/images/sool9
    - require:
      - virt: define_storage_pool_sool9
      - cmd: libvirt_python_module

# Create and start the VM using virt-install
create_vm_sool9:
  cmd.run:
    - name: |
        virt-install --name sool9 \
          --memory 4096 --vcpus 4 --cpu host \
          --disk /nsm/libvirt/images/sool9/sool9.qcow2,format=qcow2,bus=virtio \
          --disk /nsm/libvirt/images/sool9/sool9-cidata.iso,device=cdrom \
          --network bridge=br0,model=virtio \
          --os-variant=ol9.5 \
          --import \
          --noautoconsole
    - unless: virsh list --all | grep -q sool9
    - require:
      - virt: start_storage_pool_sool9
      - pkg: install_virt-install

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
