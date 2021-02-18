# Copyright 2014,2015,2016,2017,2018 Security Onion Solutions, LLC

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set interface = salt['pillar.get']('sensor:interface', 'bond0') %}
{% set ZEEKVER = salt['pillar.get']('global:mdengine', '') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set BPF_NIDS = salt['pillar.get']('nids:bpf') %}
{% set BPF_STATUS = 0  %}

{# import_yaml 'suricata/files/defaults2.yaml' as suricata #}
{% from 'suricata/suricata_config.map.jinja' import suricata_defaults as suricata_config with context %}
{% from "suricata/map.jinja" import START with context %}

# Suricata

# Add Suricata Group
suricatagroup:
  group.present:
    - name: suricata
    - gid: 940

# Add ES user
suricata:
  user.present:
    - uid: 940
    - gid: 940
    - home: /opt/so/conf/suricata
    - createhome: False

suridir:
  file.directory:
    - name: /opt/so/conf/suricata
    - user: 940
    - group: 940

suriruledir:
  file.directory:
    - name: /opt/so/conf/suricata/rules
    - user: 940
    - group: 940
    - makedirs: True

surilogdir:
  file.directory:
    - name: /opt/so/log/suricata
    - user: 940
    - group: 939

suridatadir:
  file.directory:
    - name: /nsm/suricata
    - user: 940
    - group: 939

surirulesync:
  file.recurse:
    - name: /opt/so/conf/suricata/rules/
    - source: salt://suricata/rules/
    - user: 940
    - group: 940

surilogscript:
  file.managed:
    - name: /usr/local/bin/surilogcompress
    - source: salt://suricata/cron/surilogcompress
    - mode: 755

/usr/local/bin/surilogcompress:
  cron.present:
    - user: suricata
    - minute: '17'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

suriconfigsync:
  file.managed:
    - name: /opt/so/conf/suricata/suricata.yaml
    - source: salt://suricata/files/suricata.yaml.jinja
    - context:
        suricata_config: {{ suricata_config.suricata.config }}
    - user: 940
    - group: 940
    - template: jinja

surithresholding:
  file.managed:
    - name: /opt/so/conf/suricata/threshold.conf
    - source: salt://suricata/files/threshold.conf.jinja
    - user: 940
    - group: 940
    - template: jinja

# BPF compilation and configuration
{% if BPF_NIDS %}
   {% set BPF_CALC = salt['cmd.script']('/usr/sbin/so-bpf-compile', interface + ' ' + BPF_NIDS|join(" "),cwd='/root') %}
   {% if BPF_CALC['stderr'] == "" %}
      {% set BPF_STATUS = 1  %}
   {% else  %}
suribpfcompilationfailure:
  test.configurable_test_state:
   - changes: False
   - result: False
   - comment: "BPF Syntax Error - Discarding Specified BPF"
   {% endif %}
{% endif %}

suribpf:
  file.managed:
    - name: /opt/so/conf/suricata/bpf
    - user: 940
    - group: 940
   {% if BPF_STATUS %}
    - contents_pillar: nids:bpf
   {% else %}
    - contents:
      - ""
   {% endif %}

so-suricata:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-suricata:{{ VERSION }}
    - start: {{ START }}
    - privileged: True
    - environment:
      - INTERFACE={{ interface }}
    - binds:
      - /opt/so/conf/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
      - /opt/so/conf/suricata/threshold.conf:/etc/suricata/threshold.conf:ro
      - /opt/so/conf/suricata/rules:/etc/suricata/rules:ro
      - /opt/so/log/suricata/:/var/log/suricata/:rw
      - /nsm/suricata/:/nsm/:rw
      - /opt/so/conf/suricata/bpf:/etc/suricata/bpf:ro
    - network_mode: host
    - watch:
      - file: /opt/so/conf/suricata/suricata.yaml
      - file: surithresholding
      - file: /opt/so/conf/suricata/rules/
      - file: /opt/so/conf/suricata/bpf

append_so-suricata_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-suricata
    - unless: grep -q so-suricata /opt/so/conf/so-status/so-status.conf

{% if grains.role == 'so-import' %}
disable_so-suricata_so-status.conf:
  file.comment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-suricata$
{% endif %}

/usr/local/bin/surirotate:
  cron.absent:
    - user: root
    - minute: '11'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

so-suricata-eve-clean:
  file.managed:
    - name: /usr/sbin/so-suricata-eve-clean
    - user: root
    - group: root
    - mode: 755
    - template: jinja
    - source: salt://suricata/cron/so-suricata-eve-clean

# Add eve clean cron
clean_suricata_eve_files:
  cron.present:
    - name: /usr/sbin/so-suricata-eve-clean > /dev/null 2>&1
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
