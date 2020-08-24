{%- set FLEETSETUP = salt['pillar.get']('global:fleetsetup', '0') -%}

{%- if FLEETSETUP != 0 %}
launcherpkg:
  pkg.installed:
    - sources:
      {% if grains['os'] == 'CentOS' %}
      - launcher-final: salt://launcher/packages/launcher.rpm
      {% elif grains['os'] == 'Ubuntu' %}
      - launcher-final: salt://launcher/packages/launcher.deb
      {% endif %}
{%- endif %}
