# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}

{% set kafka_ips_logstash = [] %}
{% set kafka_ips_kraft = [] %}
{% set kafkanodes =  salt['pillar.get']('kafka:nodes', {}) %}
{% set kafka_nodeid = salt['pillar.get']('kafka:nodes:' ~ GLOBALS.hostname ~ ':nodeid') %}
{% set kafka_ip = GLOBALS.node_ip %}

{% set nodes = salt['pillar.get']('kafka:nodes', {}) %}
{% set combined = [] %}
{% for hostname, data in nodes.items() %}
  {% do combined.append(data.nodeid ~ "@" ~ hostname ~ ":9093") %}
{% endfor %}
{% set kraft_controller_quorum_voters = ','.join(combined) %}

{# Create list for kafka <-> logstash/searchnode communcations #}
{% for node, node_data in kafkanodes.items() %}
{%   do kafka_ips_logstash.append(node_data['ip'] + ":9092") %}
{% endfor %}
{% set kafka_server_list = "','".join(kafka_ips_logstash) %}

{# Create a list for kraft controller <-> kraft controller communications. Used for Kafka metadata management #}
{% for node, node_data in kafkanodes.items() %}
{%   do kafka_ips_kraft.append(node_data['nodeid'] ~ "@" ~ node_data['ip'] ~ ":9093") %}
{% endfor %}
{% set kraft_server_list = "','".join(kafka_ips_kraft) %}


include:
  - ssl

kafka_group:
  group.present:
    - name: kafka
    - gid: 960

kafka:
  user.present:
    - uid: 960
    - gid: 960

{# Future tools to query kafka directly / show consumer groups
kafka_sbin_tools:
  file.recurse:
    - name: /usr/sbin
    - source: salt://kafka/tools/sbin
    - user: 960
    - group: 960
    - file_mode: 755 #}

kafka_sbin_jinja_tools:
  file.recurse:
    - name: /usr/sbin
    - source: salt://kafka/tools/sbin_jinja
    - user: 960
    - group: 960
    - file_mode: 755
    - template: jinja

kakfa_log_dir:
  file.directory:
    - name: /opt/so/log/kafka
    - user: 960
    - group: 960
    - makedirs: True

kafka_data_dir:
  file.directory:
    - name: /nsm/kafka/data
    - user: 960
    - group: 960
    - makedirs: True

kafka_keystore_script:
  cmd.script:
    - source: salt://kafka/tools/sbin_jinja/so-kafka-generate-keystore
    - template: jinja
    - cwd: /opt/so
    - defaults:
        GLOBALS: {{ GLOBALS }}

kafka_kraft_server_properties:
  file.managed:
    - source: salt://kafka/etc/server.properties.jinja
    - name: /opt/so/conf/kafka/server.properties
    - template: jinja
    - defaults:
        kafka_nodeid: {{ kafka_nodeid }}
        kraft_controller_quorum_voters: {{ kraft_controller_quorum_voters }}
        kafka_ip: {{ kafka_ip }}
    - user: 960
    - group: 960
    - makedirs: True
    - show_changes: False

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}