{% set MAINIP = salt['pillar.get']('global:managerip') %}

# This state will create the SecOps Automation user within Playbook

include:
  - playbook
  
wait_for_playbook:
  cmd.run:
    - name: until nc -z {{ MAINIP }} 3200; do sleep 1; done
    - timeout: 300

create_user:
  cmd.script:
    - source: salt://playbook/files/automation_user_create.sh
    - cwd: /root
    - template: jinja
    - onchanges:
      - cmd: wait_for_playbook
