lasthighstate:
  file.touch:
    - name: /opt/so/log/salt/lasthighstate
    - order: 9001

# set by setup; so-push-drainer does not target a node that still has it
first_highstate_pending:
  grains.absent:
    - destructive: True
    - order: 9001
