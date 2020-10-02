# This state will create the SecOps Automation user within Playbook

include:
  - playbook

salt://playbook/files/automation_user_create.sh:
  cmd.script:
    - cwd: /root
    - template: jinja
