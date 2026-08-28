# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.


{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'logstash/map.jinja' import LOGSTASH_MERGED %}
{%   set ASSIGNED_PIPELINES = LOGSTASH_MERGED.assigned_pipelines.roles[GLOBALS.role.split('-')[1]] %}

{%   if GLOBALS.role not in ['so-receiver','so-fleet'] %}
include:
  - elasticsearch
{%   endif %}

# Create the logstash group
logstashgroup:
  group.present:
    - name: logstash
    - gid: 931

logstashhome:
  file.directory:
    - name: /opt/so/conf/logstash
    - user: 931
    - group: 931
    - mode: 700
    - makedirs: True

# Add the logstash user for the log4j settings
logstash:
  user.present:
    - uid: 931
    - gid: 931
    - home: /opt/so/conf/logstash

logstash_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://logstash/tools/sbin
    - user: 931
    - group: 939
    - file_mode: 755

#logstash_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://logstash/tools/sbin_jinja
#    - user: 931
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

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

# Auto-generate Logstash pipeline config
{% for pipeline, config in LOGSTASH_MERGED.pipeline_config.items() %}
{% for assigned_pipeline in ASSIGNED_PIPELINES %}
{% set custom_pipeline = 'custom/' + pipeline + '.conf' %}
{% if custom_pipeline in LOGSTASH_MERGED.defined_pipelines[assigned_pipeline] %}
ls_custom_pipeline_conf_{{assigned_pipeline}}_{{pipeline}}:
  file.managed:
    - name: /opt/so/conf/logstash/pipelines/{{assigned_pipeline}}/{{ pipeline }}.conf
    - contents: LOGSTASH_MERGED.pipeline_config.{{pipeline}}
{% endif %}
{% endfor %}
{% endfor %}


{% for assigned_pipeline in ASSIGNED_PIPELINES %}
{# a blank per-pipeline setting falls back to the global logstash.yml value #}
{% set PARSED_OVERRIDES = LOGSTASH_MERGED.get('pipeline_settings', {}).get(assigned_pipeline, {}) %}
{% if PARSED_OVERRIDES is not mapping %}
{%   do salt.log.warning('logstash: ignoring malformed pipeline_settings for pipeline ' ~ assigned_pipeline ~ '; expected a set of settings') %}
{% endif %}
{% set PIPELINE_OVERRIDES = PARSED_OVERRIDES if PARSED_OVERRIDES is mapping else {} %}
{% set THREADS = PIPELINE_OVERRIDES.get('pipeline_x_workers') or LOGSTASH_MERGED.config.pipeline_x_workers %}
{% set BATCH = PIPELINE_OVERRIDES.get('pipeline_x_batch_x_size') or LOGSTASH_MERGED.config.pipeline_x_batch_x_size %}
    {% for CONFIGFILE in LOGSTASH_MERGED.defined_pipelines[assigned_pipeline] %}
ls_pipeline_{{assigned_pipeline}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}:
  file.managed:
    - source: salt://logstash/pipelines/config/{{CONFIGFILE}}
      {% if 'jinja' in CONFIGFILE.split('.')[-1] %}
    - name: /opt/so/conf/logstash/pipelines/{{assigned_pipeline}}/{{CONFIGFILE.split('/')[1] | replace(".jinja", "")}}
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}
        ES_USER: "{{ salt['pillar.get']('elasticsearch:auth:users:so_elastic_user:user', '') }}"
        ES_PASS: "{{ salt['pillar.get']('elasticsearch:auth:users:so_elastic_user:pass', '') }}"
        THREADS: {{ THREADS }}
        BATCH: {{ BATCH }}
      {% else %}
    - name: /opt/so/conf/logstash/pipelines/{{assigned_pipeline}}/{{CONFIGFILE.split('/')[1]}}
      {% endif %}
    - user: 931
    - group: 939
    - mode: 660
    - makedirs: True
    - show_changes: False
    {% endfor %}

ls_pipeline_{{assigned_pipeline}}:
  file.directory:
    - name: /opt/so/conf/logstash/pipelines/{{assigned_pipeline}}
    - user: 931
    - group: 939
    - require:
    {% for CONFIGFILE in LOGSTASH_MERGED.defined_pipelines[assigned_pipeline] %}
      - file: ls_pipeline_{{assigned_pipeline}}_{{CONFIGFILE.split('.')[0] | replace("/","_") }}
    {% endfor %}
    - clean: True
{% endfor %}

# Copy down all the configs
lspipelinesyml:
  file.managed:
    - name: /opt/so/conf/logstash/etc/pipelines.yml
    - source: salt://logstash/etc/pipelines.yml.jinja
    - template: jinja
    - defaults:
        ASSIGNED_PIPELINES: {{ ASSIGNED_PIPELINES }}

lslog4j2:
  file.managed:
    - name: /opt/so/conf/logstash/etc/log4j2.properties
    - source: salt://logstash/etc/log4j2.properties.jinja
    - template: jinja
    - user: 931
    - group: 939

lsetcsync:
  file.recurse:
    - name: /opt/so/conf/logstash/etc
    - source: salt://logstash/etc
    - user: 931
    - group: 939
    - template: jinja
    - clean: True
{#- both names are matched: the .jinja source so the recurse does not copy it verbatim,
    and the rendered file so clean: True does not delete what lslog4j2 wrote #}
    - exclude_pat:
      - pipelines*
      - log4j2.properties*
    - defaults:
        LOGSTASH_MERGED: {{ LOGSTASH_MERGED }}

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

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
