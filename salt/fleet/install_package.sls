{%- set FLEETMASTER = salt['pillar.get']('static:fleet_master', False) -%}
{%- set FLEETNODE = salt['pillar.get']('static:fleet_node', False) -%}

{%- if FLEETMASTER or FLEETNODE %}
launcherpkg:
  pkg.installed:
    - sources:
      {% if grains['os'] == 'CentOS' %}
      - launcher-final: salt://fleet/packages/launcher.rpm
      {% elif grains['os'] == 'Ubuntu' %}
      - launcher-final: salt://fleet/packages/launcher.deb
      {% endif %}
{%- endif %}
