{% set ENROLLSECRET = salt['cmd.run']('docker exec so-fleet fleetctl get enroll-secret') %}

so/fleet:
  event.send:
    - data:
        action: 'enablefleet'
        hostname: {{ grains.host }}
        role: {{ grains.role }}
        enroll-secret: {{ ENROLLSECRET }}