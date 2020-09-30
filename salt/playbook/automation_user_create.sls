
# This state will import the initial default playbook database. 
# If there is an existing playbook database, it will be overwritten - no backups are made.

include:
  - playbook

salt://playbook/files/create_automation_user.sh:
  cmd.script:
    - cwd: /root
    - template: jinja

'sleep 5':
  cmd.run
  