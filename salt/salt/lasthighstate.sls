lasthighstate:
  file.touch:
    - name: /opt/so/log/salt/lasthighstate
    - order: 9001

# Set by setup and the hypervisor VM cloud profile; so-push-drainer does not target a node that still has it.
# Auto-ordered states start at 10000, and a negative order runs after all of them, just before the
# order: last states, so the grain goes only once the highstate has run every state. The touch above stays
# at 9001 because so-status and so-salt-minion-check read it.
first_highstate_pending:
  grains.absent:
    - destructive: True
    - order: -1
