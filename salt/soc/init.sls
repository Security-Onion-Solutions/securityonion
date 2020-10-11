{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'soc' in top_states %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}

socdir:
  file.directory:
    - name: /opt/so/conf/soc
    - user: 939
    - group: 939
    - makedirs: True

socdatadir:
  file.directory:
    - name: /nsm/soc/jobs
    - user: 939
    - group: 939
    - makedirs: True

soclogdir:
  file.directory:
    - name: /opt/so/log/soc
    - user: 939
    - group: 939
    - makedirs: True

socconfig:
  file.managed:
    - name: /opt/so/conf/soc/soc.json
    - source: salt://soc/files/soc/soc.json
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

socchanges:
  file.managed:
    - name: /opt/so/conf/soc/changes.json
    - source: salt://soc/files/soc/changes.json
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

so-soc:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-soc:{{ VERSION }}
    - hostname: soc
    - name: so-soc
    - binds:
      - /nsm/soc/jobs:/opt/sensoroni/jobs:rw
      - /opt/so/conf/soc/soc.json:/opt/sensoroni/sensoroni.json:ro
      - /opt/so/conf/soc/changes.json:/opt/sensoroni/html/changes.json:ro
      - /opt/so/log/soc/:/opt/sensoroni/logs/:rw
    - extra_hosts:
    {%- if salt['pillar.get']('nodestab', {}) %}
      {%- for SN, SNDATA in salt['pillar.get']('nodestab', {}).items() %}
      - {{ SN.split('_')|first }}:{{ SNDATA.ip }}
      {%- endfor %}
      {%- endif %}
    - port_bindings:
      - 0.0.0.0:9822:9822
    - watch:
      - file: /opt/so/conf/soc/*

# Add Kratos Group
kratosgroup:
  group.present:
    - name: kratos
    - gid: 928

# Add Kratos user
kratos:
  user.present:
    - uid: 928
    - gid: 928
    - home: /opt/so/conf/kratos
    
kratosdir:
  file.directory:
    - name: /opt/so/conf/kratos/db
    - user: 928
    - group: 928
    - makedirs: True

kratoslogdir:
  file.directory:
    - name: /opt/so/log/kratos
    - user: 928
    - group: 928
    - makedirs: True

kratossync:
  file.recurse:
    - name: /opt/so/conf/kratos
    - source: salt://soc/files/kratos
    - user: 928
    - group: 928
    - file_mode: 600
    - template: jinja

so-kratos:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-kratos:{{ VERSION }}
    - hostname: kratos
    - name: so-kratos
    - binds:
      - /opt/so/conf/kratos/schema.json:/kratos-conf/schema.json:ro    
      - /opt/so/conf/kratos/kratos.yaml:/kratos-conf/kratos.yaml:ro
      - /opt/so/log/kratos/:/kratos-log:rw
      - /opt/so/conf/kratos/db:/kratos-data:rw
    - port_bindings:
      - 0.0.0.0:4433:4433
      - 0.0.0.0:4434:4434
    - watch:
      - file: /opt/so/conf/kratos

{% else %}

soc_state_not_allowed:
  test.fail_without_changes:
    - name: soc_state_not_allowed

{% endif %}