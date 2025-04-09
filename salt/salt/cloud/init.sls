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
{%     from 'salt/map.jinja' import SALTVERSION %}
{%     set HYPERVISORS = salt['pillar.get']('hypervisor:nodes', {} ) %}

include:
  - libvirt.packages
  - libvirt.64962
  - libvirt.ssh.users

install_salt_cloud:
  pkg.installed:
    - name: salt-cloud
    - version: {{SALTVERSION}}

{%     if HYPERVISORS %}
cloud_providers:
  file.managed:
    - name: /etc/salt/cloud.providers.d/libvirt.conf
    - source: salt://salt/cloud/cloud.providers.d/libvirt.conf.jinja
    - defaults:
        HYPERVISORS: {{HYPERVISORS}}
    - template: jinja

cloud_profiles:
  file.managed:
    - name: /etc/salt/cloud.profiles.d/socloud.conf
    - source: salt://salt/cloud/cloud.profiles.d/socloud.conf.jinja
    - defaults:
        HYPERVISORS: {{HYPERVISORS}}
        MANAGERHOSTNAME: {{ grains.host }}
        MANAGERIP: {{ pillar.host.mainip }}
    - template: jinja

{%       for role, hosts in HYPERVISORS.items() %}
{%         for host in hosts.keys() %}

hypervisor_{{host}}_{{role}}_pillar_dir:
  file.directory:
    - name: /opt/so/saltstack/local/pillar/hypervisor/{{host}}_{{role}}

{%         endfor %}
{%       endfor %}
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
