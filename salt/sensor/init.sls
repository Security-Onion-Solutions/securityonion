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

sensor_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://sensor/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

sensor_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://sensor/tools/sbin_jinja
    - user: 939
    - group: 939 
    - file_mode: 755
    - template: jinja
