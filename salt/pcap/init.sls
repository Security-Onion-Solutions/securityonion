# Copyright 2014,2015,2016,2017,2018,2019,2020,2021,2022 Security Onion Solutions, LLC

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

{% from "pcap/map.jinja" import STENOOPTIONS with context %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set INTERFACE = salt['pillar.get']('sensor:interface', 'bond0') %}
{% set BPF_STENO = salt['pillar.get']('steno:bpf', None) %}
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

{% if BPF_STENO %}
   {% set BPF_CALC = salt['cmd.script']('/usr/sbin/so-bpf-compile', INTERFACE + ' ' + BPF_STENO|join(" "),cwd='/root') %}
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
    - source: salt://pcap/files/config
    - user: stenographer
    - group: stenographer
    - mode: 644
    - template: jinja
    - defaults:
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
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-steno:{{ VERSION }}
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
