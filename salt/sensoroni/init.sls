{% from 'vars/globals.map.jinja' import GLOBALS %}

sensoroniconfdir:
  file.directory:
    - name: /opt/so/conf/sensoroni
    - user: 939
    - group: 939
    - makedirs: True

sensoroniagentconf:
  file.managed:
    - name: /opt/so/conf/sensoroni/sensoroni.json
    - source: salt://sensoroni/files/sensoroni.json
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

analyzersdir:
  file.directory:
    - name: /opt/so/conf/sensoroni/analyzers
    - user: 939
    - group: 939
    - makedirs: True

sensoronilog:
  file.directory:
    - name: /opt/so/log/sensoroni
    - user: 939
    - group: 939
    - makedirs: True

analyzerscripts:
  file.recurse:
    - name: /opt/so/conf/sensoroni/analyzers
    - user: 939
    - group: 939
    - file_mode: 755
    - template: jinja
    - source: salt://sensoroni/files/analyzers

sensoroni_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://sensoroni/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#sensoroni_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://sensoroni/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

so-sensoroni:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-soc:{{ GLOBALS.so_version }}
    - network_mode: host
    - binds:
      - /opt/so/conf/steno/certs:/etc/stenographer/certs:rw
      - /nsm/pcap:/nsm/pcap:rw
      - /nsm/import:/nsm/import:rw
      - /nsm/pcapout:/nsm/pcapout:rw
      - /opt/so/conf/sensoroni/sensoroni.json:/opt/sensoroni/sensoroni.json:ro
      - /opt/so/conf/sensoroni/analyzers:/opt/sensoroni/analyzers:rw
      - /opt/so/log/sensoroni:/opt/sensoroni/logs:rw
    - watch:
      - file: /opt/so/conf/sensoroni/sensoroni.json
    - require:
      - file: sensoroniagentconf

append_so-sensoroni_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-sensoroni
