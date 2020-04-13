{% set ENROLLSECRET = salt['pillar.get']('secrets:fleet_enroll-secret') %}
{% set CURRENTPACKAGEVERSION = salt['pillar.get']('static:fleet_package-version') %}

so/fleet:
  event.send:
    - data:
        action: 'genpackages'
        hostname: {{ grains.host }}
        role: {{ grains.role }}
        mainip: {{ grains.host }}
        enroll-secret: {{ ENROLLSECRET }}
        current-package-version: {{ CURRENTPACKAGEVERSION }}