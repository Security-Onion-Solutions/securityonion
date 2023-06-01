# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'kibana/map.jinja' import KIBANAMERGED %}

include:
{% if KIBANAMERGED.enabled %}
  - kibana.enabled
  - kibana.so_config_load
  - kibana.so_securitySolution_load
  - kibana.so_dashboard_load
{% else %}
  - kibana.disabled
{% endif %}
