# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{# Managed elasticsearch/soc_elasticsearch.yaml file for adding integration configuration items to UI #}
{% set managed_integrations = salt['pillar.get']('elasticsearch:managed_integrations', []) %}
{% if managed_integrations %}
{%   from 'elasticfleet/integration-defaults.map.jinja' import ADDON_INTEGRATION_DEFAULTS %}
{%   set addon_integration_keys = ADDON_INTEGRATION_DEFAULTS.keys() %}
{%   set matched_integration_names = [] %}
{%   for k in addon_integration_keys %}
{%     for i in managed_integrations %}
{%       if i in k %}
{%         do matched_integration_names.append(k) %}
{%       endif %}
{%     endfor %}
{%   endfor %}
{%   set es_soc_annotations = '/opt/so/saltstack/default/salt/elasticsearch/soc_elasticsearch.yaml' %}
{{   es_soc_annotations }}:
     file.serialize:
       - dataset:
           {% set data = salt['file.read'](es_soc_annotations) | load_yaml %}
           {% set es = data.get('elasticsearch', {}) %}
           {% set index_settings = es.get('index_settings', {}) %}
           {% set input = index_settings.get('so-logs', {}) %}
           {% for k in matched_integration_names %}
           {%   if k not in index_settings %}
           {%     set _ = index_settings.update({k: input}) %}
           {%   endif %}
           {% endfor %}
           {% for k in addon_integration_keys %}
           {%   if k not in matched_integration_names and k in index_settings %}
           {%     set _ = index_settings.pop(k) %}
           {%   endif %}
           {% endfor %}
           {{ data }}

{#   Managed elasticsearch/defaults.yaml file for enabling 'Revert to default' via SOC UI for newly added config items #}
{%   set es_defaults = '/opt/so/saltstack/default/salt/elasticsearch/defaults.yaml' %}
{{   es_defaults }}:
     file.serialize:
       - dataset:
           {% set data = salt['file.read'](es_defaults) | load_yaml %}
           {% set es = data.get('elasticsearch', {}) %}
           {% set index_settings = es.get('index_settings', {}) %}
           {% for k in matched_integration_names %}
           {%   if k not in index_settings %}
           {%     set input = ADDON_INTEGRATION_DEFAULTS[k] %}
           {%     set _ = index_settings.update({k: input})%}
           {%   endif %}
           {% endfor %}
           {% for k in addon_integration_keys %}
           {%   if k not in matched_integration_names and k in index_settings %}
           {%     set _ = index_settings.pop(k) %}
           {%   endif %}
           {% endfor %}
           {{ data }}
{% endif %}