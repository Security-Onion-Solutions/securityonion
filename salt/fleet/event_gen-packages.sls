{% set MANAGER = salt['grains.get']('master') %}
{% set ENROLLSECRET = salt['pillar.get']('secrets:fleet_enroll-secret') %}
{% set CURRENTPACKAGEVERSION = salt['pillar.get']('global:fleet_packages-version') %}
{% set VERSION = salt['pillar.get']('global:soversion') %}
{% set CUSTOM_FLEET_HOSTNAME = salt['pillar.get']('global:fleet_custom_hostname', None) %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{%- set FLEETNODE = salt['pillar.get']('global:fleet_node') -%}

{% if CUSTOM_FLEET_HOSTNAME != None and CUSTOM_FLEET_HOSTNAME != '' %}
   {% set HOSTNAME =  CUSTOM_FLEET_HOSTNAME  %}
{% elif FLEETNODE %}
   {% set HOSTNAME = grains.host  %}
{% else %}
   {% set HOSTNAME = salt['pillar.get']('global:url_base')  %}
{% endif %}

so/fleet:
  event.send:
    - data:
        action: 'genpackages'
        package-hostname: {{ HOSTNAME }}
        role: {{ grains.role }}
        mainip: {{ grains.host }}
        enroll-secret: {{ ENROLLSECRET }}
        current-package-version: {{ CURRENTPACKAGEVERSION }}
        manager: {{ MANAGER }}
        version: {{ VERSION }}
        imagerepo: {{ IMAGEREPO }}