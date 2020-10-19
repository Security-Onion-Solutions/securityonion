# Copyright 2014,2015,2016,2017,2018,2019,2020 Security Onion Solutions, LLC

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
{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'pcap' in top_states %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set INTERFACE = salt['pillar.get']('sensor:interface', 'bond0') %}
{% set BPF_STENO = salt['pillar.get']('steno:bpf', None) %}
{% set BPF_COMPILED = "" %}
{% from "pcap/map.jinja" import START with context %}

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

sensoroniconfdir:
  file.directory:
    - name: /opt/so/conf/sensoroni
    - user: 939
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

sensoroniagentconf:
  file.managed:
    - name: /opt/so/conf/sensoroni/sensoroni.json
    - source: salt://pcap/files/sensoroni.json
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

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

sensoronilog:
  file.directory:
    - name: /opt/so/log/sensoroni
    - user: 939
    - group: 939
    - makedirs: True

so-steno:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-steno:{{ VERSION }}
    - start: {{ START }}
    - network_mode: host
    - privileged: True
    - port_bindings:
      - 127.0.0.1:1234:1234
    - binds:
      - /opt/so/conf/steno/certs:/etc/stenographer/certs:rw
      - /opt/so/conf/steno/config:/etc/stenographer/config:rw
      - /nsm/pcap:/nsm/pcap:rw
      - /nsm/pcapindex:/nsm/pcapindex:rw
      - /nsm/pcaptmp:/tmp:rw
      - /opt/so/log/stenographer:/var/log/stenographer:rw
    - watch:
      - file: /opt/so/conf/steno/config

so-sensoroni:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-soc:{{ VERSION }}
    - network_mode: host
    - binds:
      - /opt/so/conf/steno/certs:/etc/stenographer/certs:rw
      - /nsm/pcap:/nsm/pcap:rw
      - /nsm/import:/nsm/import:rw
      - /nsm/pcapout:/nsm/pcapout:rw
      - /opt/so/conf/sensoroni/sensoroni.json:/opt/sensoroni/sensoroni.json:ro
      - /opt/so/log/sensoroni:/opt/sensoroni/logs:rw
    - watch:
      - file: /opt/so/conf/sensoroni/sensoroni.json

{% else %}

pcap_state_not_allowed:
  test.fail_without_changes:
    - name: pcap_state_not_allowed

{% endif %}