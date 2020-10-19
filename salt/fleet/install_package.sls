{%- set FLEETMANAGER = salt['pillar.get']('global:fleet_manager', False) -%}
{%- set FLEETNODE = salt['pillar.get']('global:fleet_node', False) -%}
{%- set FLEETHOSTNAME = salt['pillar.get']('global:fleet_hostname', False) -%}
{%- set FLEETIP = salt['pillar.get']('global:fleet_ip', False) -%}
{% set CUSTOM_FLEET_HOSTNAME = salt['pillar.get']('global:fleet_custom_hostname', None) %}

{% if CUSTOM_FLEET_HOSTNAME != (None and '') %}

{{ CUSTOM_FLEET_HOSTNAME }}:
  host.present:
    - ip: {{ FLEETIP }}
    - clean: True

{% elif FLEETNODE and grains['role'] != 'so-fleet' %}

{{ FLEETHOSTNAME }}:
  host.present:
    - ip: {{ FLEETIP }}
    - clean: True

{% endif %}

launcherpkg:
  pkg.installed:
    - sources:
      {% if grains['os'] == 'CentOS' %}
      - launcher-final: salt://fleet/packages/launcher.rpm
      {% elif grains['os'] == 'Ubuntu' %}
      - launcher-final: salt://fleet/packages/launcher.deb
      {% endif %}
