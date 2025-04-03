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

{% if 'vrt' in salt['pillar.get']('features', []) %}

{%   from 'hypervisor/map.jinja' import HYPERVISORS %}

hypervisor_annotation:
  file.managed:
    - name: /opt/so/saltstack/default/salt/hypervisor/soc_hypervisor.yaml
    - source: salt://soc/dyanno/hypervisor/soc_hypervisor.yaml.jinja
    - template: jinja
    - user: socore
    - group: socore
    - defaults:
        HYPERVISORS: {{ HYPERVISORS }}
        baseDomainStatus: {{ salt['pillar.get']('baseDomain:status', 'Initialized') }}

{%   for role in HYPERVISORS %}
{%     for hypervisor in HYPERVISORS[role].keys() %}
hypervisor_host_directory_{{hypervisor}}:
  file.directory:
    - name: /opt/so/saltstack/local/salt/hypervisor/hosts/{{hypervisor}}
    - makedirs: True
    - user: socore
    - group: socore
    - recurse:
      - user
      - group
{%     endfor %}
{%   endfor %}

{% else %}

{{sls}}_no_license_detected:
  test.fail_without_changes:
    - name: {{sls}}_no_license_detected
    - comment:
      - "Hypervisor nodes are a feature supported only for customers with a valid license.
      Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com
      for more information about purchasing a license to enable this feature."

{% endif %}
