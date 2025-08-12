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

include:
  - hypervisor
  - libvirt.packages

nsm_libvirt_images:
  file.directory:
    - name: /nsm/libvirt/images/sool9
    - dir_mode: 775
    - file_mode: 640
    - recurse:
      - mode
    - makedirs: True

# Remove hash file if image isn't present. This will allow for the image to redownload and initialize.
remove_sha256_sool9:
  file.absent:
    - name: /nsm/libvirt/images/sool9/sool9.sha256
    - unless: test -f /nsm/libvirt/images/sool9/sool9.qcow2

# Manage SHA256 hash file
manage_sha256_sool9:
  file.managed:
    - name: /nsm/libvirt/images/sool9/sool9.sha256
    - source: salt://libvirt/images/sool9/sool9.sha256

# Manage cloud-init files
manage_metadata_sool9:
  file.managed:
    - name: /nsm/libvirt/images/sool9/meta-data
    - source: salt://libvirt/images/sool9/meta-data

manage_userdata_sool9:
  file.managed:
    - name: /nsm/libvirt/images/sool9/user-data
    - source: salt://libvirt/images/sool9/user-data
    - show_changes: False

# Manage qcow2 image
manage_qcow2_sool9:
  file.managed:
    - name: /nsm/libvirt/images/sool9/sool9.qcow2
    - source: salt://libvirt/images/sool9/sool9.qcow2
    - onchanges:
      - file: manage_sha256_sool9
      - file: manage_metadata_sool9
      - file: manage_userdata_sool9

manage_cidata_sool9:
  file.managed:
    - name: /nsm/libvirt/images/sool9/sool9-cidata.iso
    - source: salt://libvirt/images/sool9/sool9-cidata.iso
    - onchanges:
      - file: manage_qcow2_sool9

# Define the storage pool
define_storage_pool_sool9:
  virt.pool_defined:
    - name: sool9
    - ptype: dir
    - target: /nsm/libvirt/images/sool9
    - require:
      - file: manage_metadata_sool9
      - file: manage_userdata_sool9
      - file: manage_cidata_sool9
      - cmd: libvirt_python_module
    - unless:
      - virsh pool-list --all | grep -q sool9

# Set pool autostart
set_pool_autostart_sool9:
  cmd.run:
    - name: virsh pool-autostart sool9
    - require:
      - virt: define_storage_pool_sool9
    - unless:
      - virsh pool-info sool9 | grep -q "Autostart.*yes"

# Start the storage pool
start_storage_pool_sool9:
  cmd.run:
    - name: virsh pool-start sool9
    - require:
      - virt: define_storage_pool_sool9
      - cmd: libvirt_python_module
    - unless:
      - virsh pool-info sool9 | grep -q "State.*running"

# Stop the VM if running and base image files change
stop_vm_sool9:
  module.run:
    - virt.stop:
      - name: sool9
    - onchanges:
      - file: manage_qcow2_sool9
      - file: manage_metadata_sool9
      - file: manage_userdata_sool9
      - file: manage_cidata_sool9
    - require_in:
      - module: undefine_vm_sool9
    - onlyif:
      # Only try to stop if VM is actually running
      - virsh list --state-running --name | grep -q sool9

undefine_vm_sool9:
  module.run:
    - virt.undefine:
      - vm_: sool9
    - onchanges:
      - file: manage_qcow2_sool9
      - file: manage_metadata_sool9
      - file: manage_userdata_sool9
      - file: manage_cidata_sool9
    # Note: When VM doesn't exist, you'll see "error: failed to get domain 'sool9'" - this is expected
    # [ERROR   ] Command 'virsh' failed with return code: 1
    # [ERROR   ] stdout: error: failed to get domain 'sool9'
    - onlyif:
      - virsh dominfo sool9

# Create and start the VM, letting cloud-init run
create_vm_sool9:
  cmd.run:
    - name: |
        virt-install --name sool9 \
          --memory 12288 --vcpus 8 --cpu host-model \
          --disk /nsm/libvirt/images/sool9/sool9.qcow2,format=qcow2,bus=virtio \
          --disk /nsm/libvirt/images/sool9/sool9-cidata.iso,device=cdrom \
          --network bridge=br0,model=virtio \
          --os-variant=ol9.5 \
          --import \
          --noautoconsole
    - require:
      - cmd: start_storage_pool_sool9
      - pkg: install_virt-install
    - onchanges:
      - file: manage_qcow2_sool9
      - file: manage_metadata_sool9
      - file: manage_userdata_sool9
      - file: manage_cidata_sool9

# Wait for cloud-init to complete and VM to shutdown
wait_for_cloud_init_sool9:
  cmd.run:
    - name: /usr/sbin/so-wait-cloud-init -n sool9
    - require:
      - cmd: create_vm_sool9
    - onchanges:
      - cmd: create_vm_sool9
    - timeout: 600

# Configure network predictability after cloud-init
configure_network_predictable_sool9:
  cmd.run:
    - name: /usr/sbin/so-qcow2-network-predictable -n sool9
    - require:
      - cmd: wait_for_cloud_init_sool9
    - onchanges:
      - cmd: create_vm_sool9

# Fire event here that causes soc.dyanno.hypervisor state to be applied
base_domain_ready:
  event.send:
    - name: soc/dyanno/hypervisor/baseDomain
    - data:
        status: 'Initialized'
    - require:
      - cmd: configure_network_predictable_sool9
    - onchanges:
      - cmd: create_vm_sool9

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
