{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set logscan_cpu_period = salt['pillar.get']('logscan:cpu_period', 10000) %}

logscan_data_dir:
  file.directory:
    - name: /nsm/logscan/data
    - user: 939
    - group: 939
    - makedirs: True

logscan_conf_dir:
  file.directory:
    - name: /opt/so/conf/logscan
    - user: 939
    - group: 939
    - makedirs: True

logscan_conf:
  file.managed:
    - name: /opt/so/conf/logscan/logscan.conf
    - source: salt://logscan/files/logscan.conf
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

logscan_log_dir:
  file.directory:
    - name: /opt/so/log/logscan
    - user: 939
    - group: 939

so-logscan:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-logscan:{{ VERSION }}
    - hostname: logscan
    - name: so-logscan
    - binds:
      - /nsm/logscan/data:/logscan/data:rw
      - /opt/so/conf/logscan.conf:/logscan/logscan.conf:ro
      - /opt/so/log/logscan:/logscan/output:rw
      - /opt/so/log:/logscan/logs:ro
    - cpu_period: {{ logscan_cpu_period }}
