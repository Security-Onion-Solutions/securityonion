
# This state will create the SecOps Automation user within Playbook

include:
  - playbook

salt://playbook/files/create_automation_user.sh:
  cmd.script:
    - cwd: /root
    - template: jinja
