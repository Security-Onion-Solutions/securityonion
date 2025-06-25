# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'suricata/map.jinja' import SURICATAMERGED %}

include:
  - suricata.pcap
{% if SURICATAMERGED.enabled and GLOBALS.role != 'so-import' %}
  - suricata.enabled
{% elif GLOBALS.role == 'so-import' %}
  - suricata.config
  - suricata.disabled
{% else %}
  - suricata.disabled
{% endif %}
