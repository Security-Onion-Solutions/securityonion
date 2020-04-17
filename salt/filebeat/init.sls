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
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}
{% set MASTERIP = salt['pillar.get']('static:masterip', '') %}
{% set FEATURES = salt['pillar.get']('elastic:features', False) %}
{% if FEATURES %}
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
# This needs to be owned by root
filebeatconfsync:
  file.managed:
    - name: /opt/so/conf/filebeat/etc/filebeat.yml
    - source: salt://filebeat/etc/filebeat.yml
    - user: 0
    - group: 0
    - template: jinja
so-filebeat:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-filebeat:{{ VERSION }}{{ FEATURES }}
    - hostname: so-filebeat
    - user: root
    - extra_hosts: {{ MASTER }}:{{ MASTERIP }}
    - binds:
      - /opt/so/log/filebeat:/usr/share/filebeat/logs:rw
      - /opt/so/conf/filebeat/etc/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /nsm/zeek:/nsm/zeek:ro
      - /nsm/strelka/log:/nsm/strelka/log:ro
      - /opt/so/log/suricata:/suricata:ro
      - /opt/so/wazuh/logs/alerts:/wazuh/alerts:ro
      - /opt/so/wazuh/logs/archives:/wazuh/archives:ro
      - /nsm/osquery/fleet/:/nsm/osquery/fleet:ro
      - /opt/so/conf/filebeat/etc/pki/filebeat.crt:/usr/share/filebeat/filebeat.crt:ro
      - /opt/so/conf/filebeat/etc/pki/filebeat.key:/usr/share/filebeat/filebeat.key:ro
      - /etc/ssl/certs/intca.crt:/usr/share/filebeat/intraca.crt:ro
    - watch:
      - file: /opt/so/conf/filebeat/etc/filebeat.yml
