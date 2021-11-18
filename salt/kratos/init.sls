{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}

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
    - source: salt://kratos/files
    - user: 928
    - group: 928
    - file_mode: 600
    - template: jinja

kratos_schema:
  file.exists:
    - name: /opt/so/conf/kratos/schema.json
  
kratos_yaml:
  file.exists:
    - name: /opt/so/conf/kratos/kratos.yaml

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
    - restart_policy: unless-stopped
    - watch:
      - file: /opt/so/conf/kratos
    - require:
      - file: kratos_schema
      - file: kratos_yaml
      - file: kratoslogdir
      - file: kratosdir

append_so-kratos_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-kratos

wait_for_kratos:
  http.wait_for_successful_query:
    - name: 'http://{{ MANAGER }}:4434/'
    - ssl: True
    - verify_ssl: False
    - status:
      - 200
      - 301
      - 302
      - 404
    - status_type: list
    - wait_for: 300
    - request_interval: 10
    - require:
      -  docker_container: so-kratos

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
