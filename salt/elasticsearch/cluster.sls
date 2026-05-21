# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'elasticsearch/config.map.jinja' import ELASTICSEARCHMERGED %}
{%   from 'elasticsearch/template.map.jinja' import ES_INDEX_SETTINGS, SO_MANAGED_INDICES %}
{%   if GLOBALS.role != 'so-heavynode' %}
{%     from 'elasticsearch/template.map.jinja' import ALL_ADDON_SETTINGS %}
{%   endif %}

escomponenttemplates:
  file.recurse:
    - name: /opt/so/conf/elasticsearch/templates/component
    - source: salt://elasticsearch/templates/component
    - user: 930
    - group: 939
    - clean: True
    - onchanges_in:
      - file: so-elasticsearch-templates-reload
    - show_changes: False

# Clean up legacy and non-SO managed templates from the elasticsearch/templates/index/ directory
so_index_template_dir:
  file.directory:
    - name: /opt/so/conf/elasticsearch/templates/index
    - clean: True
    {%- if SO_MANAGED_INDICES %}
    - require:
      {%- for index in SO_MANAGED_INDICES %}
      - file: so_index_template_{{index}}
      {%- endfor %}
    {%- endif %}

# Auto-generate index templates for SO managed indices (directly defined in elasticsearch/defaults.yaml)
#   These index templates are for the core SO datasets and are always required
{%  for index, settings in ES_INDEX_SETTINGS.items() %}
{%    if settings.index_template is defined %}
so_index_template_{{index}}:
  file.managed:
    - name: /opt/so/conf/elasticsearch/templates/index/{{ index }}-template.json
    - source: salt://elasticsearch/base-template.json.jinja
    - defaults:
        TEMPLATE_CONFIG: {{ settings.index_template }}
    - template: jinja
    - onchanges_in:
      - file: so-elasticsearch-templates-reload
{%    endif %}
{%  endfor %}

{%  if GLOBALS.role != "so-heavynode" %}
# Auto-generate optional index templates for integration | input | content packages
#   These index templates are not used by default (until user adds package to an agent policy).
#   Pre-configured with standard defaults, and incorporated into SOC configuration for user customization.
{%    for index,settings in ALL_ADDON_SETTINGS.items() %}
{%      if settings.index_template is defined %}
addon_index_template_{{index}}:
  file.managed:
    - name: /opt/so/conf/elasticsearch/templates/addon-index/{{ index }}-template.json
    - source: salt://elasticsearch/base-template.json.jinja
    - defaults:
        TEMPLATE_CONFIG: {{ settings.index_template }}
    - template: jinja
    - show_changes: False
    - onchanges_in:
      - file: addon-elasticsearch-templates-reload
{%       endif %}
{%     endfor %}
{%   endif %}

{%  if GLOBALS.role in GLOBALS.manager_roles %}
so-es-cluster-settings:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-cluster-settings
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: elasticsearch_sbin_jinja
      - http: wait_for_so-elasticsearch
{%  endif %}

# heavynodes will only load ILM policies for SO managed indices. (Indicies defined in elasticsearch/defaults.yaml)
so-elasticsearch-ilm-policy-load:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-ilm-policy-load
    - cwd: /opt/so
    - require:
      - docker_container: so-elasticsearch
      - file: so-elasticsearch-ilm-policy-load-script
    - onchanges:
      - file: so-elasticsearch-ilm-policy-load-script

so-elasticsearch-templates-reload:
  file.absent:
    - name: /opt/so/state/estemplates.txt

addon-elasticsearch-templates-reload:
  file.absent:
    - name: /opt/so/state/addon_estemplates.txt

# so-elasticsearch-templates-load will have its first successful run during the 'so-elastic-fleet-setup' script
so-elasticsearch-templates:
  cmd.run:
{%-  if GLOBALS.role == "so-heavynode" %}
    - name: /usr/sbin/so-elasticsearch-templates-load --heavynode
{%-  else %}
    - name: /usr/sbin/so-elasticsearch-templates-load
{%-  endif %}
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: elasticsearch_sbin_jinja

so-elasticsearch-pipelines:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-pipelines {{ GLOBALS.hostname }}
    - require:
      - docker_container: so-elasticsearch
      - file: so-elasticsearch-pipelines-script

so-elasticsearch-roles-load:
  cmd.run:
    - name: /usr/sbin/so-elasticsearch-roles-load
    - cwd: /opt/so
    - template: jinja
    - require:
      - docker_container: so-elasticsearch
      - file: elasticsearch_sbin_jinja

{%  if grains.role in ['so-managersearch', 'so-manager', 'so-managerhype'] %}
{%    set ap = "absent" %}
{%  endif %}
{%  if grains.role in ['so-eval', 'so-standalone', 'so-heavynode'] %}
{%    if ELASTICSEARCHMERGED.index_clean %}
{%      set ap = "present" %}
{%    else %}
{%      set ap = "absent" %}
{%    endif %}
{%  endif %}
{%  if grains.role in ['so-eval', 'so-standalone', 'so-managersearch', 'so-heavynode', 'so-manager'] %}
so-elasticsearch-indices-delete:
  cron.{{ap}}:
    - name: /usr/sbin/so-elasticsearch-indices-delete > /opt/so/log/elasticsearch/cron-elasticsearch-indices-delete.log 2>&1
    - identifier: so-elasticsearch-indices-delete
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
{%  endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
