# Copyright 2014,2015,2016,2017,2018,2019,2020,2021 Security Onion Solutions, LLC

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

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}

include:
  - ssl

# Redis Setup
redisconfdir:
  file.directory:
    - name: /opt/so/conf/redis/etc
    - user: 939
    - group: 939
    - makedirs: True

redisworkdir:
  file.directory:
    - name: /opt/so/conf/redis/working
    - user: 939
    - group: 939
    - makedirs: True

redislogdir:
  file.directory:
    - name: /opt/so/log/redis
    - user: 939
    - group: 939
    - makedirs: True

redisconf:
  file.managed:
    - name: /opt/so/conf/redis/etc/redis.conf
    - source: salt://redis/etc/redis.conf
    - user: 939
    - group: 939
    - template: jinja

so-redis:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-redis:{{ VERSION }}
    - hostname: so-redis
    - user: socore
    - port_bindings:
      - 0.0.0.0:6379:6379
      - 0.0.0.0:9696:9696
    - binds:
      - /opt/so/log/redis:/var/log/redis:rw
      - /opt/so/conf/redis/etc/redis.conf:/usr/local/etc/redis/redis.conf:ro
      - /opt/so/conf/redis/working:/redis:rw
      - /etc/pki/redis.crt:/certs/redis.crt:ro
      - /etc/pki/redis.key:/certs/redis.key:ro
  {% if grains['role'] in ['so-manager', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - /etc/pki/ca.crt:/certs/ca.crt:ro
  {% else %}
      - /etc/ssl/certs/intca.crt:/certs/ca.crt:ro
  {% endif %}
    - entrypoint: "redis-server /usr/local/etc/redis/redis.conf"
    - watch:
      - file: /opt/so/conf/redis/etc
    - require:
      - file: redisconf
      - x509: redis_crt
      - x509: redis_key
  {% if grains['role'] in ['so-manager', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import'] %}
      - x509: pki_public_ca_crt
  {% else %}
      - x509: trusttheca
  {% endif %}

append_so-redis_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-redis

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
