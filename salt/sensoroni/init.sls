{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}

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

sensoronilog:
  file.directory:
    - name: /opt/so/log/sensoroni
    - user: 939
    - group: 939
    - makedirs: True

so-sensoroni:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-soc:{{ VERSION }}
    - network_mode: host
    - binds:
      - /opt/so/conf/steno/certs:/etc/stenographer/certs:rw
      - /nsm/pcap:/nsm/pcap:rw
      - /nsm/import:/nsm/import:rw
      - /nsm/pcapout:/nsm/pcapout:rw
      - /opt/so/conf/sensoroni/sensoroni.json:/opt/sensoroni/sensoroni.json:ro
      - /opt/so/log/sensoroni:/opt/sensoroni/logs:rw
    - watch:
      - file: /opt/so/conf/sensoroni/sensoroni.json
    - require:
      - file: sensoroniagentconf

append_so-sensoroni_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-sensoroni
