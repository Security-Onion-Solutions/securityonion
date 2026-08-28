# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{# Managed elasticsearch/soc_elasticsearch.yaml file for adding integration configuration items to UI #}
{% set managed_integrations = salt['pillar.get']('manager:managed_integrations', []) %}
{% if managed_integrations and salt['file.file_exists']('/opt/so/state/esfleet_package_components.json') and salt['file.file_exists']('/opt/so/state/esfleet_component_templates.json') %}
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
{%   set soc_annotation_lines = [] %}
{%   set defaults_lines = [] %}
{%   for k in matched_integration_names %}
{%     do soc_annotation_lines.append('    ' ~ k ~ ': *dataStreamSettings') %}
{%     do defaults_lines.append('    ' ~ k ~ ':') %}
{%     set defaults_yaml = salt['slsutil.serialize']('yaml', ADDON_INTEGRATION_DEFAULTS[k], default_flow_style=False).strip() %}
{%     for line in defaults_yaml.splitlines() %}
{%       do defaults_lines.append('      ' ~ line) %}
{%     endfor %}
{%   endfor %}
{%   set es_soc_annotations = '/opt/so/saltstack/default/salt/elasticsearch/soc_elasticsearch.yaml' %}
manage_soc_annotations:
  file.blockreplace:
    - name: {{ es_soc_annotations }}
    - marker_start: '    # START managed SOC integration annotations'
    - marker_end: '    # END managed SOC integration annotations'
    - content: {{ soc_annotation_lines | join('\n') | tojson }}
    - insert_after_match: '^    # Managed SOC integration annotations are inserted below this line\.'
    - append_if_not_found: False
    - show_changes: True

{#   Managed elasticsearch/defaults.yaml file for enabling 'Revert to default' via SOC UI for newly added config items #}
{%   set es_defaults = '/opt/so/saltstack/default/salt/elasticsearch/defaults.yaml' %}
{{   es_defaults }}:
  file.blockreplace:
    - marker_start: '    # START managed SOC integration defaults'
    - marker_end: '    # END managed SOC integration defaults'
    - content: {{ defaults_lines | join('\n') | tojson }}
    - insert_after_match: '^  index_settings:$'
    - append_if_not_found: False
    - show_changes: True
{% endif %}
