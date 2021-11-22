{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set MANAGERIP = salt['pillar.get']('manager:mainip', '') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
thehiveconfdir:
  file.directory:
    - name: /opt/so/conf/thehive/etc
    - makedirs: True
    - user: 939
    - group: 939

thehivelogdir:
  file.directory:
    - name: /opt/so/log/thehive
    - makedirs: True
    - user: 939
    - group: 939

thehiveconf:
  file.recurse:
    - name: /opt/so/conf/thehive/etc
    - source: salt://thehive/etc
    - user: 939
    - group: 939
    - template: jinja

cortexconfdir:
  file.directory:
    - name: /opt/so/conf/cortex
    - makedirs: True
    - user: 939
    - group: 939

cortexlogdir:
  file.directory:
    - name: /opt/so/log/cortex
    - makedirs: True
    - user: 939
    - group: 939

cortexconf:
  file.recurse:
    - name: /opt/so/conf/cortex
    - source: salt://thehive/etc
    - user: 939
    - group: 939
    - template: jinja

cortexanalyzers:
  file.directory:
    - name: /opt/so/conf/cortex/custom-analyzers
    - user: 939
    - group: 939
    - template: jinja

cortexresponders:
  file.directory:
    - name: /opt/so/conf/cortex/custom-responders
    - user: 939
    - group: 939
    - template: jinja

# Install Elasticsearch

# Made directory for ES data to live in
thehiveesdata:
  file.directory:
    - name: /nsm/thehive/esdata
    - makedirs: True
    - user: 939
    - group: 939

thehive_elasticsearch_yml:
  file.exists:
    - name: /opt/so/conf/thehive/etc/es/elasticsearch.yml

log4j2_properties:
  file.exists:
    - name: /opt/so/conf/thehive/etc/es/log4j2.properties

so-thehive-es:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-thehive-es:{{ VERSION }}
    - hostname: so-thehive-es
    - name: so-thehive-es
    - user: 939
    - interactive: True
    - tty: True
    - binds:
      - /nsm/thehive/esdata:/usr/share/elasticsearch/data:rw
      - /opt/so/conf/thehive/etc/es/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro
      - /opt/so/conf/thehive/etc/es/log4j2.properties:/usr/share/elasticsearch/config/log4j2.properties:ro
      - /opt/so/log/thehive:/var/log/elasticsearch:rw
    - environment:
      - ES_JAVA_OPTS=-Xms512m -Xmx512m
    - port_bindings:
      - 0.0.0.0:9400:9400
      - 0.0.0.0:9500:9500
    - require:
      - file: thehive_elasticsearch_yml
      - file: log4j2_properties

append_so-thehive-es_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-thehive-es

cortex_application_conf:
  file.exists:
    - name: /opt/so/conf/thehive/etc/cortex-application.conf

application_conf:
  file.exists:
    - name: /opt/so/conf/thehive/etc/application.conf

# Install Cortex
so-cortex:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-thehive-cortex:{{ VERSION }}
    - hostname: so-cortex
    - name: so-cortex
    - user: 939
    - binds:
      - /opt/so/conf/thehive/etc/cortex-application.conf:/opt/cortex/conf/application.conf:ro
      - /opt/so/conf/cortex/custom-analyzers:/custom-analyzers:ro
      - /opt/so/conf/cortex/custom-responders:/custom-responders:ro
    - port_bindings:
      - 0.0.0.0:9001:9001
    - require:
      - file: cortex_application_conf

append_so-cortex_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-cortex

cortexscript:
  cmd.script:
    - source: salt://thehive/scripts/cortex_init
    - cwd: /opt/so
    - template: jinja
    - hide_output: False

so-thehive:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-thehive:{{ VERSION }}
    - environment:
      - ELASTICSEARCH_HOST={{ MANAGERIP }}
    - hostname: so-thehive
    - name: so-thehive
    - user: 939
    - binds:
      - /opt/so/conf/thehive/etc/application.conf:/opt/thehive/conf/application.conf:ro
    - port_bindings:
      - 0.0.0.0:9000:9000
    - require:
      - file: application_conf

append_so-thehive_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-thehive

thehivescript:
  cmd.script:
    - source: salt://thehive/scripts/hive_init
    - cwd: /opt/so
    - template: jinja
    - hide_output: False

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
