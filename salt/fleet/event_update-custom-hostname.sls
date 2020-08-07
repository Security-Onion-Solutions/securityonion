{% set CUSTOM_FLEET_HOSTNAME = salt['pillar.get']('global:fleet_custom_hostname', None) %}

so/fleet:
  event.send:
    - data:
        action: 'update_custom_hostname'
        custom_hostname: {{ CUSTOM_FLEET_HOSTNAME }}
        role: {{ grains.role }}
        