offload_script:
  file.managed:
    - name: /etc/NetworkManager/dispatcher.d/pre-up.d/99-so-checksum-offload-disable
    - source: salt://sensor/files/99-so-checksum-offload-disable
    - mode: 755
    - template: jinja

execute_checksum:
  cmd.run:
    - name: /etc/NetworkManager/dispatcher.d/pre-up.d/99-so-checksum-offload-disable
    - onchanges:
      - file: offload_script
