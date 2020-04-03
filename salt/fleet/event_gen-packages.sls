{% set ENROLLSECRET = salt['pillar.get']('auth:fleet_enroll-secret') %}

so/fleet:
  event.send:
    - data:
        action: 'genpackages'
        hostname: {{ grains.host }}
        role: {{ grains.role }}
        mainip: {{ grains.host }}
        enroll-secret: {{ ENROLLSECRET }}