{%- set FLEETMASTER = salt['pillar.get']('static:fleet_master', False) -%}
{%- set FLEETNODE = salt['pillar.get']('static:fleet_node', False) -%}
{%- set FLEETHOSTNAME = salt['pillar.get']('static:fleet_hostname', False) -%}
{%- set FLEETIP = salt['pillar.get']('static:fleet_ip', False) -%}
{% set CUSTOM_FLEET_HOSTNAME = salt['pillar.get']('static:fleet_custom_hostname', None) %}

{% if CUSTOM_FLEET_HOSTNAME != None or CUSTOM_FLEET_HOSTNAME != '' %}

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
