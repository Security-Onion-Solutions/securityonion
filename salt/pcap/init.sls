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
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.1.4') %}
{% set MASTER = salt['grains.get']('master') %}
# PCAP Section

# Create the logstash group
stenographergroup:
  group.present:
    - name: stenographer
    - gid: 941

# Add the logstash user for the jog4j settings
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

{% set interface = salt['pillar.get']('sensor:interface', 'bond0') %}
{% set bpf_global = salt['pillar.get']('static:steno:bpf', None) %}
{% set bpf_steno = salt['pillar.get']('steno:bpf', None) %}

{% if bpf_steno != None or bpf_global != None %}
   {% if bpf_steno != None %}
      {% set bpf_calc = salt['cmd.script']('salt://pcap/files/compile_bpf.sh', interface + ' ' + bpf_steno) %}
   {% else %}
      {% set bpf_calc = salt['cmd.script']('salt://pcap/files/compile_bpf.sh', interface + ' ' + bpf_global) %}
   {% endif %}
   {% if bpf_calc['stderr'] == "" %}
      {% set bpf_compiled = bpf_calc['stdout'] %}
   {% else  %}
         {% set bpf_compiled = None %}

bpfcompilationfailure:
  test.configurable_test_state:
   - name: bpfcompfailure
   - changes: False
   - result: False
   - comment: "BPF Compilation Failed - Discarding specified BPF"

   {% endif %}
{% else  %}
   {% set bpf_compiled = None %}
{% endif %}

stenoconf:
  file.managed:
    - name: /opt/so/conf/steno/config
    - source: salt://pcap/files/config
    - user: root
    - group: root
    - mode: 644
    - template: jinja
    - defaults:
        bpf_compiled: ""
{% if bpf_compiled != None %}
    - context:
        bpf_compiled: ',"--filter={{ bpf_compiled }}"'
{% endif %}

sensoroniagentconf:
  file.managed:
    - name: /opt/so/conf/steno/sensoroni.json
    - source: salt://pcap/files/sensoroni.json
    - user: root
    - group: root
    - mode: 644
    - template: jinja

stenoca:
  file.directory:
    - name: /opt/so/conf/steno/certs
    - user: 941
    - group: 941

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
    - user: 941
    - group: 941
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
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-steno:{{ VERSION }}
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
      - /nsm/pcapout:/nsm/pcapout:rw
      - /opt/so/log/stenographer:/var/log/stenographer:rw
      - /opt/so/conf/steno/sensoroni.json:/opt/sensoroni/sensoroni.json:ro
      - /opt/so/log/stenographer:/opt/sensoroni/logs:rw
    - watch:
      - file: /opt/so/conf/steno/config
      - file: /opt/so/conf/steno/sensoroni.json
