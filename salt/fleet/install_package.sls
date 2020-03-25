{%- set FLEETMASTER = salt['pillar.get']('static:fleet_master', False) -%}
{%- set FLEETNODE = salt['pillar.get']('static:fleet_node', False) -%}
{%- set FLEETHOSTNAME = salt['pillar.get']('static:fleet_hostname', False) -%}
{%- set FLEETIP = salt['pillar.get']('static:fleet_ip', False) -%}

{%- if FLEETMASTER or FLEETNODE %}

{{ FLEETHOSTNAME }}:
  host.present:
    - ip: {{ FLEETIP }}
    - clean: True

launcherpkg:
  pkg.installed:
    - sources:
      {% if grains['os'] == 'CentOS' %}
      - launcher-final: salt://fleet/packages/launcher.rpm
      {% elif grains['os'] == 'Ubuntu' %}
      - launcher-final: salt://fleet/packages/launcher.deb
      {% endif %}
{%- endif %}
