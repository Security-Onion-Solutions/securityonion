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
{%- set MASTER = grains['master'] %}
{%- set MASTERIP = salt['pillar.get']('static:masterip', '') %}

# Filebeat Setup
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
  file.recurse:
    - name: /opt/so/conf/filebeat/etc
    - source: salt://filebeat/etc
    - user: 0
    - group: 0
    - template: jinja

#filebeatcrt:
#  file.managed:
#    - name: /opt/so/conf/filebeat/etc/pki/filebeat.crt
#    - source: salt://filebeat/files/filebeat.crt

#filebeatkey:
#  file.managed:
#    - name: /opt/so/conf/filebeat/etc/pki/filebeat.key
#    - source: salt://filebeat/files/filebeat.key

so-filebeatimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-filebeat:HH1.1.1

so-filebeat:
  docker_container.running:
    - require:
      - so-filebeatimage
    - image: docker.io/soshybridhunter/so-filebeat:HH1.1.1
    - hostname: so-filebeat
    - user: root
    - extra_hosts: {{ MASTER }}:{{ MASTERIP }}
    - binds:
      - /opt/so/log/filebeat:/usr/share/filebeat/logs:rw
      - /opt/so/conf/filebeat/etc/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /nsm/bro:/nsm/bro:ro
      - /opt/so/log/suricata:/suricata:ro
      - /opt/so/wazuh/logs/alerts/:/wazuh/alerts:ro
      - /opt/so/wazuh/logs/archives/:/wazuh/archives:ro
      - /opt/so/log/fleet/:/osquery/logs:ro
{%- if grains['role'] == 'so-master' %}
      - /etc/pki/filebeat.crt:/usr/share/filebeat/filebeat.crt:ro
      - /etc/pki/filebeat.key:/usr/share/filebeat/filebeat.key:ro
{%- else %}
      - /opt/so/conf/filebeat/etc/pki/filebeat.crt:/usr/share/filebeat/filebeat.crt:ro
      - /opt/so/conf/filebeat/etc/pki/filebeat.key:/usr/share/filebeat/filebeat.key:ro
{%- endif %}
      - /etc/ssl/certs/intca.crt:/usr/share/filebeat/intraca.crt:ro
    - watch:
      - file: /opt/so/conf/filebeat/etc
