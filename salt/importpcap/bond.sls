configure_bond0:
  network.managed:
    - name: bond0
    - type: bond
    - enabled: True