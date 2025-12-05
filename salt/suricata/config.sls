# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   from 'suricata/map.jinja' import SURICATAMERGED %}
{%   from 'bpf/suricata.map.jinja' import SURICATABPF, SURICATA_BPF_STATUS, SURICATA_BPF_CALC %}

{%   if GLOBALS.pcap_engine in ["SURICATA", "TRANSITION"] %}
{%     from 'bpf/pcap.map.jinja' import PCAPBPF, PCAP_BPF_STATUS, PCAP_BPF_CALC %}
# BPF compilation and configuration
{%     if PCAPBPF and not PCAP_BPF_STATUS %}
suriPCAPbpfcompilationfailure:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "BPF Syntax Error - Discarding Specified BPF. Error: {{ PCAP_BPF_CALC['stderr'] }}"
{%     endif %}
{%   endif %}

suridir:
  file.directory:
    - name: /opt/so/conf/suricata
    - user: 940
    - group: 939
    - mode: 775
    - makedirs: True

# BPF applied to all of Suricata - alerts/metadata/pcap
suribpf:
  file.managed:
    - name: /opt/so/conf/suricata/bpf
    - user: 940
    - group: 940
   {% if SURICATA_BPF_STATUS %}
    - contents: {{ SURICATABPF }}
   {% else %}
    - contents:
      - ""
   {% endif %}

{%   if SURICATABPF and not SURICATA_BPF_STATUS %}
suribpfcompilationfailure:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "BPF Syntax Error - Discarding Specified BPF. Error: {{ SURICATA_BPF_CALC['stderr'] }}"
{%   endif %}

# Add Suricata Group
suricatagroup:
  group.present:
    - name: suricata
    - gid: 940

# Add Suricata user
suricata:
  user.present:
    - uid: 940
    - gid: 940
    - home: /nsm/suricata
    - createhome: False

socoregroupwithsuricata:
  group.present:
    - name: socore
    - gid: 939
    - addusers:
      - suricata

suricata_sbin:
  file.recurse:
    - name: /usr/sbin
    - source: salt://suricata/tools/sbin
    - user: 939
    - group: 939
    - file_mode: 755

suricata_sbin_jinja:
  file.recurse:
    - name: /usr/sbin
    - source: salt://suricata/tools/sbin_jinja
    - user: 939
    - group: 939 
    - file_mode: 755
    - template: jinja

suriruledir:
  file.directory:
    - name: /opt/so/rules/suricata
    - user: 940
    - group: 939
    - mode: 775
    - makedirs: True

surilogdir:
  file.directory:
    - name: /opt/so/log/suricata
    - user: 940
    - group: 939

surinsmdir:
  file.directory:
    - name: /nsm/suricata
    - user: 940
    - group: 939
    - mode: 755
    - makedirs: True

suridatadir:
  file.directory:
    - name: /nsm/suricata/extracted
    - user: 940
    - group: 939
    - mode: 770
    - makedirs: True

surirulesync:
  file.recurse:
    - name: /opt/so/rules/suricata/
    - source: salt://suricata/rules/
    - user: 940
    - group: 939
    - show_changes: False

surilogscript:
  file.managed:
    - name: /usr/local/bin/surilogcompress
    - source: salt://suricata/cron/surilogcompress
    - mode: 755

surilogcompress:
  cron.present:
    - name: /usr/local/bin/surilogcompress
    - identifier: surilogcompress
    - user: suricata
    - minute: '17'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

suriconfig:
  file.managed:
    - name: /opt/so/conf/suricata/suricata.yaml
    - source: salt://suricata/files/suricata.yaml.jinja
    - context:
        suricata_config: {{ SURICATAMERGED.config }}
    - user: 940
    - group: 940
    - template: jinja

surithresholding:
  file.managed:
    - name: /opt/so/conf/suricata/threshold.conf
    - source: salt://suricata/files/threshold.conf
    - user: 940
    - group: 940

suriclassifications:
  file.managed:
    - name: /opt/so/conf/suricata/classification.config
    - source: salt://suricata/classification/classification.config
    - user: 940
    - group: 940

so-suricata-eve-clean:
  file.managed:
    - name: /usr/sbin/so-suricata-eve-clean
    - user: root
    - group: root
    - mode: 755
    - template: jinja
    - source: salt://suricata/cron/so-suricata-eve-clean

so-suricata-rulestats:
  file.managed:
    - name: /usr/sbin/so-suricata-rulestats
    - user: root
    - group: root
    - mode: 755
    - source: salt://suricata/cron/so-suricata-rulestats

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
