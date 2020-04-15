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

{% set interface = salt['pillar.get']('sensor:interface', 'bond0') %}
{% set BROVER = salt['pillar.get']('static:broversion', '') %}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}
{% set BPF_NIDS = salt['pillar.get']('nids:bpf') %}
{% set BPF_STATUS = 0  %}

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

surirulesync:
  file.recurse:
    - name: /opt/so/conf/suricata/rules/
    - source: salt://suricata/rules/
    - user: 940
    - group: 940

suriconfigsync:
  file.managed:
    - name: /opt/so/conf/suricata/suricata.yaml
    {%- if BROVER != 'SURICATA' %}
    - source: salt://suricata/files/suricata.yaml
    {%- else %}
    - source: salt://suricata/files/suricataMETA.yaml
    {%- endif %}
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
    - image: {{ MASTER }}:5000/soshybridhunter/so-suricata:{{ VERSION }}
    - privileged: True
    - environment:
      - INTERFACE={{ interface }}
    - binds:
      - /opt/so/conf/suricata/suricata.yaml:/etc/suricata/suricata.yaml:ro
      - /opt/so/conf/suricata/threshold.conf:/etc/suricata/threshold.conf:ro
      - /opt/so/conf/suricata/rules:/etc/suricata/rules:ro
      - /opt/so/log/suricata/:/var/log/suricata/:rw
      - /opt/so/conf/suricata/bpf:/etc/suricata/bpf:ro
    - network_mode: host
    - watch:
      - file: /opt/so/conf/suricata/suricata.yaml
      - file: surithresholding
      - file: /opt/so/conf/suricata/rules/
      - file: /opt/so/conf/suricata/bpf
