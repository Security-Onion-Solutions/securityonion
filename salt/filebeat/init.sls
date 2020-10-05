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

{% if 'filebeat' in top_states %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set MANAGERIP = salt['pillar.get']('global:managerip', '') %}
{% set FEATURES = salt['pillar.get']('elastic:features', False) %}
{%- if FEATURES is sameas true %}
  {% set FEATURES = "-features" %}
{% else %}
  {% set FEATURES = '' %}
{% endif %}
filebeatetcdir:
  file.directory:
    - name: /opt/so/conf/filebeat/etc
    - user: 939
    - group: 939
    - makedirs: True
filebeatlogdir:
  file.directory:
    - name: /opt/so/log/filebeat
    - user: 939
    - group: 939
    - makedirs: True
filebeatpkidir:
  file.directory:
    - name: /opt/so/conf/filebeat/etc/pki
    - user: 939
    - group: 939
    - makedirs: True
fileregistrydir:
  file.directory:
    - name: /opt/so/conf/filebeat/registry
    - user: 939
    - group: 939
    - makedirs: True
# This needs to be owned by root
filebeatconfsync:
  file.managed:
    - name: /opt/so/conf/filebeat/etc/filebeat.yml
    - source: salt://filebeat/etc/filebeat.yml
    - user: 0
    - group: 0
    - template: jinja
    - defaults:
        INPUTS: {{ salt['pillar.get']('filebeat:config:inputs', {}) }}
        OUTPUT: {{ salt['pillar.get']('filebeat:config:output', {}) }}
so-filebeat:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-filebeat:{{ VERSION }}{{ FEATURES }}
    - hostname: so-filebeat
    - user: root
    - extra_hosts: {{ MANAGER }}:{{ MANAGERIP }}
    - binds:
      - /nsm:/nsm:ro
      - /opt/so/log/filebeat:/usr/share/filebeat/logs:rw
      - /opt/so/conf/filebeat/etc/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /nsm/wazuh/logs/alerts:/wazuh/alerts:ro
      - /nsm/wazuh/logs/archives:/wazuh/archives:ro
      - /opt/so/conf/filebeat/etc/pki/filebeat.crt:/usr/share/filebeat/filebeat.crt:ro
      - /opt/so/conf/filebeat/etc/pki/filebeat.key:/usr/share/filebeat/filebeat.key:ro
      - /opt/so/conf/filebeat/registry:/usr/share/filebeat/data/registry:rw
      - /etc/ssl/certs/intca.crt:/usr/share/filebeat/intraca.crt:ro
    - port_bindings:
        - 0.0.0.0:514:514/udp
    - watch:
      - file: /opt/so/conf/filebeat/etc/filebeat.yml

{% else %}

filebeat_state_not_allowed:
  test.fail_without_changes:
    - name: filebeat_state_not_allowed

{% endif %}
