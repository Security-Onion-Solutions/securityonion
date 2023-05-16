# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'zeek/config.map.jinja' import ZEEKMERGED %}

include:
{% if ZEEKMERGED.enabled and GLOBALS.role != 'so-import' and GLOBALS.md_engine != 'SURICATA' %}
  - zeek.enabled
{% elif GLOBALS.role == 'so-import' %}
  - zeek.config
  - zeek.disabled
{% else %}
  - zeek.disabled
{% endif %}
