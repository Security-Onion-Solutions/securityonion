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
{% if sls.split('.')[0] in allowed_states %}
{%   if 'vrt' in salt['pillar.get']('features', []) %}
{% set manager_hostname = grains.id.split('_')[0] %}

# Check if hypervisor environment has been set up
{% set ssh_user_exists = salt['user.info']('soqemussh') %}
{% set ssh_keys_exist = salt['file.file_exists']('/etc/ssh/auth_keys/soqemussh/id_ecdsa') and 
                        salt['file.file_exists']('/etc/ssh/auth_keys/soqemussh/id_ecdsa.pub') and
                        salt['file.file_exists']('/opt/so/saltstack/local/salt/libvirt/ssh/keys/id_ecdsa.pub') %}
{% set base_image_exists = salt['file.file_exists']('/nsm/libvirt/boot/OL9U5_x86_64-kvm-b253.qcow2') %}
{% set vm_files_exist = salt['file.directory_exists']('/opt/so/saltstack/local/salt/libvirt/images/sool9') and
                        salt['file.file_exists']('/opt/so/saltstack/local/salt/libvirt/images/sool9/sool9.qcow2') and
                        salt['file.file_exists']('/opt/so/saltstack/local/salt/libvirt/images/sool9/sool9-cidata.iso') %}
{% set hypervisor_host_dir_exists = salt['file.directory_exists']('/opt/so/saltstack/local/salt/hypervisor/hosts/' ~ manager_hostname) %}

{% if ssh_user_exists and ssh_keys_exist and base_image_exists and vm_files_exist and hypervisor_host_dir_exists %}
# Hypervisor environment is already set up, include the necessary states
include:
  - hypervisor
  - libvirt
  - libvirt.images

hypervisor_setup_verified:
  test.succeed_without_changes:
    - name: Hypervisor environment is already set up
    - comment: All required files and configurations for the hypervisor environment exist

{% else %}
# Hypervisor environment needs to be set up
run_setup_hypervisor:
  salt.runner:
    - name: setup_hypervisor.setup_environment
    - minion_id: {{ grains.id }}
{% endif %}

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
