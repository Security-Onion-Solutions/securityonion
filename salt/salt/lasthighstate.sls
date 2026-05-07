lasthighstate:
  file.touch:
    - name: /opt/so/log/salt/lasthighstate
    - order: 9001
