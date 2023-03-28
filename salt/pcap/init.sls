# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from "pcap/map.jinja" import STENOOPTIONS with context %}
{% from "pcap/config.map.jinja" import PCAPMERGED with context %}
{% from 'bpf/pcap.map.jinja' import PCAPBPF %}

{% set BPF_COMPILED = "" %}

# PCAP Section

stenographergroup:
  group.present:
    - name: stenographer
    - gid: 941

stenographer:
  user.present:
    - uid: 941
    - gid: 941
    - home: /opt/so/conf/steno

stenoconfdir:
  file.directory:
    - name: /opt/so/conf/steno
    - user: 941
    - group: 939
    - makedirs: True

{% if PCAPBPF %}
   {% set BPF_CALC = salt['cmd.script']('/usr/sbin/so-bpf-compile', GLOBALS.sensor.interface + ' ' + PCAPBPF|join(" "),cwd='/root') %}
   {% if BPF_CALC['stderr'] == "" %}
      {% set BPF_COMPILED =  ",\\\"--filter=" + BPF_CALC['stdout'] + "\\\""  %}
   {% else  %}

bpfcompilationfailure:
  test.configurable_test_state:
   - changes: False
   - result: False
   - comment: "BPF Compilation Failed - Discarding Specified BPF"
   {% endif %}
{% endif %}

stenoconf:
  file.managed:
    - name: /opt/so/conf/steno/config
    - source: salt://pcap/files/config.jinja
    - user: stenographer
    - group: stenographer
    - mode: 644
    - template: jinja
    - defaults:
        PCAPMERGED: {{ PCAPMERGED }}
        BPF_COMPILED: "{{ BPF_COMPILED }}"

stenoca:
  file.directory:
    - name: /opt/so/conf/steno/certs
    - user: 941
    - group: 939

pcapdir:
  file.directory:
    - name: /nsm/pcap
    - user: 941
    - group: 941
    - makedirs: True

pcaptmpdir:
  file.directory:
    - name: /nsm/pcaptmp
    - user: 941
    - group: 941
    - makedirs: True

pcapoutdir:
  file.directory:
    - name: /nsm/pcapout
    - user: 939
    - group: 939
    - makedirs: True

pcapindexdir:
  file.directory:
    - name: /nsm/pcapindex
    - user: 941
    - group: 941
    - makedirs: True

stenolog:
  file.directory:
    - name: /opt/so/log/stenographer
    - user: 941
    - group: 941
    - makedirs: True

so-steno:
  docker_container.{{ STENOOPTIONS.status }}:
  {% if STENOOPTIONS.status == 'running' %}
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-steno:{{ GLOBALS.so_version }}
    - start: {{ STENOOPTIONS.start }}
    - network_mode: host
    - privileged: True
    - binds:
      - /opt/so/conf/steno/certs:/etc/stenographer/certs:rw
      - /opt/so/conf/steno/config:/etc/stenographer/config:rw
      - /nsm/pcap:/nsm/pcap:rw
      - /nsm/pcapindex:/nsm/pcapindex:rw
      - /nsm/pcaptmp:/tmp:rw
      - /opt/so/log/stenographer:/var/log/stenographer:rw
    - watch:
      - file: stenoconf
    - require:
      - file: stenoconf
  {% else %} {# if stenographer isn't enabled, then stop and remove the container #}
    - force: True
  {% endif %}

append_so-steno_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-steno
    - unless: grep -q so-steno /opt/so/conf/so-status/so-status.conf

  {% if not STENOOPTIONS.start %}
so-steno_so-status.disabled:
  file.comment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-steno$
  {% else %}
delete_so-steno_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-steno$
  {% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
