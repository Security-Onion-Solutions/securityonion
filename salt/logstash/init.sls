# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.


{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

  {% from 'logstash/map.jinja' import REDIS_NODES with context %}
  {% from 'vars/globals.map.jinja' import GLOBALS %}

  # Logstash Section - Decide which pillar to use
  {% set lsheap = salt['pillar.get']('logstash_settings:lsheap') %}
  {% if GLOBALS.role in ['so-eval','so-managersearch', 'so-manager', 'so-standalone'] %}
    {% set nodetype = GLOBALS.role  %}
  {% endif %}

  {% set PIPELINES = salt['pillar.get']('logstash:pipelines', {}) %}
  {% set DOCKER_OPTIONS = salt['pillar.get']('logstash:docker_options', {}) %}
  {% set TEMPLATES = salt['pillar.get']('elasticsearch:templates', {}) %}

include:
  - ssl
  {% if GLOBALS.role not in ['so-receiver'] %}
  - elasticsearch
  {% endif %}

# Create the logstash group
logstashgroup:
  group.present:
    - name: logstash
    - gid: 931

# Add the logstash user for the jog4j settings
logstash:
  user.present:
    - uid: 931
    - gid: 931
    - home: /opt/so/conf/logstash

lslibdir:
  file.absent:
    - name: /opt/so/conf/logstash/lib

lsetcdir:
  file.directory:
    - name: /opt/so/conf/logstash/etc
    - user: 931
    - group: 939
    - makedirs: True

lspipelinedir:
  file.directory:
    - name: /opt/so/conf/logstash/pipelines
    - user: 931
    - group: 939

  {% for PL in PIPELINES %}
    {% for CONFIGFILE in PIPELINES[PL].config %}
ls_pipeline_{{PL}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}:
  file.managed:
    - source: salt://logstash/pipelines/config/{{CONFIGFILE}}
      {% if 'jinja' in CONFIGFILE.split('.')[-1] %}
    - name: /opt/so/conf/logstash/pipelines/{{PL}}/{{CONFIGFILE.split('/')[1] | replace(".jinja", "")}}
    - template: jinja
      {% else %}
    - name: /opt/so/conf/logstash/pipelines/{{PL}}/{{CONFIGFILE.split('/')[1]}}
      {% endif %}
    - user: 931
    - group: 939
    - mode: 660
    - makedirs: True
    - show_changes: False
    {% endfor %}

ls_pipeline_{{PL}}:
  file.directory:
    - name: /opt/so/conf/logstash/pipelines/{{PL}}
    - user: 931
    - group: 939
    - require:
    {% for CONFIGFILE in PIPELINES[PL].config %}
      - file: ls_pipeline_{{PL}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}
    {% endfor %}
    - clean: True

  {% endfor %}

lspipelinesyml:
  file.managed:
    - name: /opt/so/conf/logstash/etc/pipelines.yml
    - source: salt://logstash/etc/pipelines.yml.jinja
    - template: jinja
    - defaults:
        pipelines: {{ PIPELINES }}

# Copy down all the configs
lsetcsync:
  file.recurse:
    - name: /opt/so/conf/logstash/etc
    - source: salt://logstash/etc
    - user: 931
    - group: 939
    - template: jinja
    - clean: True
    - exclude_pat: pipelines*

# Create the import directory
importdir:
  file.directory:
    - name: /nsm/import
    - user: 931
    - group: 939
    - makedirs: True

# Create the logstash data directory
nsmlsdir:
  file.directory:
    - name: /nsm/logstash/tmp
    - user: 931
    - group: 939
    - makedirs: True

# Create the log directory
lslogdir:
  file.directory:
    - name: /opt/so/log/logstash
    - user: 931
    - group: 939
    - makedirs: True

so-logstash:
  docker_container.running:
    - image: {{ GLOBALS.manager }}:5000/{{ GLOBALS.image_repo }}/so-logstash:{{ GLOBALS.so_version }}
    - hostname: so-logstash
    - name: so-logstash
    - user: logstash
    - extra_hosts: {{ REDIS_NODES }}
    - environment:
      - LS_JAVA_OPTS=-Xms{{ lsheap }} -Xmx{{ lsheap }}
    - port_bindings:
  {% for BINDING in DOCKER_OPTIONS.port_bindings %}
      - {{ BINDING }}
  {% endfor %}
    - binds:
      - /opt/so/conf/elasticsearch/templates/:/templates/:ro
      - /opt/so/conf/logstash/etc/:/usr/share/logstash/config/:ro
      - /opt/so/conf/logstash/pipelines:/usr/share/logstash/pipelines:ro
      - /opt/so/rules:/etc/nsm/rules:ro
      - /nsm/import:/nsm/import:ro
      - /nsm/logstash:/usr/share/logstash/data:rw
      - /opt/so/log/logstash:/var/log/logstash:rw
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
      - /opt/so/conf/logstash/etc/certs:/usr/share/logstash/certs:ro
  {% if GLOBALS.role in ['so-manager', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-receiver'] %}
      - /etc/pki/filebeat.crt:/usr/share/logstash/filebeat.crt:ro
      - /etc/pki/filebeat.p8:/usr/share/logstash/filebeat.key:ro
  {% endif %}
  {% if GLOBALS.role in ['so-manager', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - /etc/pki/ca.crt:/usr/share/filebeat/ca.crt:ro
  {% else %}
      - /etc/ssl/certs/intca.crt:/usr/share/filebeat/ca.crt:ro
  {% endif %}
  {% if GLOBALS.role in ['so-manager', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-searchnode'] %}
      - /opt/so/conf/ca/cacerts:/etc/pki/ca-trust/extracted/java/cacerts:ro
      - /opt/so/conf/ca/tls-ca-bundle.pem:/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem:ro
  {% endif %}
  {%- if GLOBALS.role == 'so-eval' %}
      - /nsm/zeek:/nsm/zeek:ro
      - /nsm/suricata:/suricata:ro
      - /opt/so/log/fleet/:/osquery/logs:ro
      - /opt/so/log/strelka:/strelka:ro
  {%- endif %}
    - watch:
      - file: lsetcsync
  {% for PL in PIPELINES %}
      - file: ls_pipeline_{{PL}}
    {% for CONFIGFILE in PIPELINES[PL].config %}
      - file: ls_pipeline_{{PL}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}
    {% endfor %}
  {% endfor %}
    - require:
  {% if grains['role'] in ['so-manager', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-receiver'] %}
      - x509: etc_filebeat_crt
  {% endif %}
  {% if grains['role'] in ['so-manager', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - x509: pki_public_ca_crt
  {% else %}
      - x509: trusttheca
  {% endif %}
  {% if grains.role in ['so-manager', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - file: cacertz
      - file: capemz
  {% endif %}

append_so-logstash_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-logstash

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
