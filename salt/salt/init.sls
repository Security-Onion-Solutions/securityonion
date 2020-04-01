salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True
