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

{% set mainint = salt['pillar.get']('host:mainint', 'enp1s0') %}
{% set interfaces = salt['network.interfaces']() %}
{% set non_enp1s0_interfaces = [] %}
{% for iface, data in interfaces.items() %}
  {% if iface != mainint and not iface.startswith(('veth', 'docker', 'lo', 'br', 'sobridge', 'bond')) %}
    {% do non_enp1s0_interfaces.append(iface) %}
  {% endif %}
{% endfor %}

# Create bond0 interface with NetworkManager
bond0_interface:
  cmd.run:
    - name: |
        nmcli con add type bond \
          con-name bond0 \
          ifname bond0 \
          mode 0 \
          miimon 100 \
          ipv4.method disabled \
          ipv6.method ignore \
          ipv6.addr-gen-mode default \
          connection.autoconnect yes
        nmcli con mod bond0 ethernet.mtu 9000
        nmcli con up bond0
    - unless: nmcli con show bond0
{% if non_enp1s0_interfaces|length > 0 %}
    - require_in:
{% for iface in non_enp1s0_interfaces %}
      - cmd: {{ iface }}_slave
{% endfor %}
{% endif %}

# Configure non-enp1s0 interfaces as bond slaves first
{% if non_enp1s0_interfaces|length > 0 %}
{% for iface in non_enp1s0_interfaces %}
{{ iface }}_slave:
  cmd.run:
    - name: |
        nmcli con add type ethernet \
          con-name bond0-slave-{{ iface }} \
          ifname {{ iface }} \
          master bond0 \
          slave-type bond \
          ethernet.mtu 9000
        nmcli con up bond0-slave-{{ iface }}
    - unless: nmcli con show bond0-slave-{{ iface }}
{% endfor %}
{% endif %}

{% else %}
{{sls}}_no_license_detected:
  test.fail_without_changes:
    - name: {{sls}}_no_license_detected
    - comment:
      - "Hypervisor nodes are a feature supported only for customers with a valid license.
      Contact Security Onion Solutions, LLC via our website at https://securityonionsolutions.com
      for more information about purchasing a license to enable this feature."
{% endif %}
