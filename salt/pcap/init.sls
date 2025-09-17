# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'pcap/config.map.jinja' import PCAPMERGED %}

include:
{% if PCAPMERGED.enabled and GLOBALS.role != 'so-import'%}
  - pcap.enabled
{% elif GLOBALS.role == 'so-import' %}
  - pcap.config
  - pcap.disabled
{% else %}
  - pcap.disabled
{% endif %}

# This directory needs to exist regardless of whether STENO is enabled or not, in order for
# Sensoroni to be able to look at old steno PCAP data

# if stenographer has never run as the pcap engine no 941 user is created, so we use socore as a placeholder.
# /nsm/pcap is empty until stenographer is used as pcap engine
{% set pcap_id = 941 %}
{% set user_list = salt['user.list_users']() %}
{% if GLOBALS.pcap_engine == "SURICATA" and 'stenographer' not in user_list %}
{%   set pcap_id = 939 %}
{% endif %}
pcapdir:
  file.directory:
    - name: /nsm/pcap
    - user: {{ pcap_id }}
    - group: {{ pcap_id }}
    - makedirs: True

pcapoutdir:
  file.directory:
    - name: /nsm/pcapout
    - user: 939
    - group: 939
    - makedirs: True
