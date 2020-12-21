{% set ENROLLSECRET = salt['cmd.run']('docker exec so-fleet fleetctl get enroll-secret default') %}

so/fleet:
  event.send:
    - data:
        action: 'update-enrollsecret'
        enroll-secret: {{ ENROLLSECRET }}