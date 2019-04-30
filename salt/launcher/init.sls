{%- set FLEETSETUP = salt['pillar.get']('static:fleetsetup', '0') -%}

{%- if FLEETSETUP != 0 %}
launcherpkg:
  pkg.installed:
    - sources:
      {% if grains['os'] == 'CentOS' %}
      - launcher: salt://launcher/packages/launcher.rpm
      {% elif grains['os'] == 'Ubuntu' %}
      - launcher: salt://launcher/packages/launcher.deb
      {% endif %}
{%- endif %}
