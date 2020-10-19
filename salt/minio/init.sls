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
{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'minio' in top_states %}

{% set access_key = salt['pillar.get']('minio:access_key', '') %}
{% set access_secret = salt['pillar.get']('minio:access_secret', '') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}

# Minio Setup
minioconfdir:
  file.directory:
    - name: /opt/so/conf/minio/etc/certs
    - user: 939
    - group: 939
    - makedirs: True

miniodatadir:
  file.directory:
    - name: /nsm/minio/data/
    - user: 939
    - group: 939
    - makedirs: True

logstashbucket:
  file.directory:
    - name: /nsm/minio/data/logstash
    - user: 939
    - group: 939
    - makedirs: True

so-minio:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-minio:{{ VERSION }}
    - hostname: so-minio
    - user: socore
    - port_bindings:
      - 0.0.0.0:9595:9595
    - environment:
      - MINIO_ACCESS_KEY: {{ access_key }}
      - MINIO_SECRET_KEY: {{ access_secret }}
    - binds:
      - /nsm/minio/data:/data:rw
      - /opt/so/conf/minio/etc:/.minio:rw
      - /etc/pki/minio.key:/.minio/certs/private.key:ro
      - /etc/pki/minio.crt:/.minio/certs/public.crt:ro
    - entrypoint: "/usr/bin/docker-entrypoint.sh server --certs-dir /.minio/certs --address :9595 /data"

{% else %}

minio_state_not_allowed:
  test.fail_without_changes:
    - name: minio_state_not_allowed

{% endif %}