configure_bond0:
  network.managed:
    - name: bond0
    - type: bond
    - mode: '1'
    - enabled: True