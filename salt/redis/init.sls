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
{% set lsaccessip = salt['pillar.get']('master:lsaccessip', '') %}

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

redisconfsync:
  file.recurse:
    - name: /opt/so/conf/redis/etc
    - source: salt://redis/etc
    - user: 939
    - group: 939
    - template: jinja

so-redisimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false soshybridhunter/so-redis:HH1.0.7

so-redis:
  docker_container.running:
    - require:
      - so-redisimage
    - image: soshybridhunter/so-redis:HH1.0.7
    - hostname: so-redis
    - user: socore
    - port_bindings:
      - 0.0.0.0:6379:6379
    - binds:
      - /opt/so/log/redis:/var/log/redis:rw
      - /opt/so/conf/redis/etc/redis.conf:/usr/local/etc/redis/redis.conf:ro
      - /opt/so/conf/redis/working:/redis:rw
    - entrypoint: "redis-server /usr/local/etc/redis/redis.conf"
