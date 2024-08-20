# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{%   from 'salt/map.jinja' import SALTVERSION %}
{%   set HYPERVISORS = salt['pillar.get']('hypervisor:nodes', {} ) %}

include:
  - libvirt.packages

install_salt_cloud:
  pkg.installed:
    - name: salt-cloud
    - version: {{SALTVERSION}}

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
    - template: jinja

{%   for role, hosts in HYPERVISORS.items() %}
{%     for host in hosts.keys() %}

hypervisor_{{host}}_{{role}}_pillar_dir:
  file.directory:
    - name: /opt/so/saltstack/local/pillar/hypervisor/{{host}}_{{role}}

{%     endfor %}
{%   endfor %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
