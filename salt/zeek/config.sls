# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from "zeek/config.map.jinja" import ZEEKMERGED %}
{% from 'bpf/zeek.map.jinja' import ZEEKBPF %}
{% set BPF_STATUS = 0  %}

# Add Zeek group
zeekgroup:
  group.present:
    - name: zeek
    - gid: 937

# Add Zeek User
zeek:
  user.present:
    - uid: 937
    - gid: 937
    - home: /home/zeek

# Create some directories
zeekpolicydir:
  file.directory:
    - name: /opt/so/conf/zeek/policy
    - user: 937
    - group: 939
    - makedirs: True

# Zeek Log Directory
zeeklogdir:
  file.directory:
    - name: /nsm/zeek/logs
    - user: 937
    - group: 939
    - makedirs: True

# Zeek Spool Directory
zeekspooldir:
  file.directory:
    - name: /nsm/zeek/spool/manager
    - user: 937
    - makedirs: True

# Zeek extracted
zeekextractdir:
  file.directory:
    - name: /nsm/zeek/extracted
    - user: 937
    - group: 939
    - mode: 770
    - makedirs: True

zeekextractcompletedir:
  file.directory:
    - name: /nsm/zeek/extracted/complete
    - user: 937
    - group: 939
    - mode: 770
    - makedirs: True

# Sync the policies
zeekpolicysync:
  file.recurse:
    - name: /opt/so/conf/zeek/policy
    - source: salt://zeek/policy
    - user: 937
    - group: 939
    - template: jinja
    - defaults:
        FILE_EXTRACTION: {{ ZEEKMERGED.file_extraction }}

# Ensure the zeek spool tree (and state.db) ownership is correct
zeekspoolownership:
  file.directory:
    - name: /nsm/zeek/spool
    - user: 937
zeekstatedbownership:
  file.managed:
    - name: /nsm/zeek/spool/state.db
    - user: 937
    - replace: False
    - create: False

zeek_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://zeek/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

#zeek_sbin_jinja:
#  file.recurse:
#    - name: /usr/sbin
#    - source: salt://zeek/tools/sbin_jinja
#    - user: 939
#    - group: 939 
#    - file_mode: 755
#    - template: jinja

# Sync Intel
zeekintelloadsync:
  file.managed:
    - name: /opt/so/conf/policy/intel/__load__.zeek
    - source: salt://zeek/policy/intel/__load__.zeek
    - user: 937
    - group: 939
    - makedirs: True

zeekctlcfg:
  file.managed:
    - name: /opt/so/conf/zeek/zeekctl.cfg
    - source: salt://zeek/files/zeekctl.cfg.jinja
    - user: 937
    - group: 939
    - template: jinja
    - defaults:
        ZEEKCTL: {{ ZEEKMERGED.config.zeekctl | tojson }}

# Sync node.cfg
nodecfg:
  file.managed:
    - name: /opt/so/conf/zeek/node.cfg
    - source: salt://zeek/files/node.cfg.jinja
    - user: 937
    - group: 939
    - template: jinja
    - defaults:
        NODE: {{ ZEEKMERGED.config.node }}

networkscfg:
  file.managed:
    - name: /opt/so/conf/zeek/networks.cfg
    - source: salt://zeek/files/networks.cfg.jinja
    - user: 937
    - group: 939
    - template: jinja
    - defaults:
        NETWORKS: {{ ZEEKMERGED.config.networks }}

plcronscript:
  file.managed:
    - name: /usr/local/bin/packetloss.sh
    - source: salt://zeek/cron/packetloss.sh
    - mode: 755

# BPF compilation and configuration
{% if ZEEKBPF %}
   {% set BPF_CALC = salt['cmd.script']('salt://common/tools/sbin/so-bpf-compile', GLOBALS.sensor.interface + ' ' + ZEEKBPF|join(" "),cwd='/root') %}
   {% if BPF_CALC['stderr'] == "" %}
       {% set BPF_STATUS = 1  %}
  {% else  %}
zeekbpfcompilationfailure:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "BPF Syntax Error - Discarding Specified BPF"
   {% endif %}
{% endif %}

zeekbpf:
  file.managed:
    - name: /opt/so/conf/zeek/bpf
    - user: 940
    - group: 940
{% if BPF_STATUS %}
    - contents: {{ ZEEKBPF }}
{% else %}
    - contents:
      - "ip or not ip"
{% endif %}

localzeek:
  file.managed:
    - name: /opt/so/conf/zeek/local.zeek
    - source: salt://zeek/files/local.zeek.jinja
    - user: 937
    - group: 939
    - template: jinja
    - defaults:
        LOCAL: {{ ZEEKMERGED.config.local | tojson }}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
