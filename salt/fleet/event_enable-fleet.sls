{% set ENROLLSECRET = salt['cmd.run']('docker exec so-fleet fleetctl get enroll-secret') %}
{%- set MAINIP = salt['pillar.get']('node:mainip') -%}

so/fleet:
  event.send:
    - data:
        action: 'enablefleet'
        hostname: {{ grains.host }}
        mainip: {{ MAINIP }}
        role: {{ grains.role }}
        enroll-secret: {{ ENROLLSECRET }}