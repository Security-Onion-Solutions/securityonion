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
filebeatconfdir:
  file.directory:
    - name: /opt/so/conf/filebeat
    - user: 939
    - group: 939
    - makedirs: True

filebeatconfsync:
  file.recurse:
    - name: /opt/so/conf/filebeat/etc
    - source: salt://filebeat/etc
    - user: 939
    - group: 939
    - template: jinja

docker.elastic.co/beats/filebeat:6.2.4:
  docker_image.present

so-filebeat:
  docker_container.running:
    - image: docker.elastic.co/beats/filebeat:6.2.4
    - hostname: so-filebeat
    - binds:
      - /opt/so/log/filebeat:/var/log/filebeat:rw
      - /opt/so/conf/redis/etc/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /nsm/bro/spool/manager:/nsm/bro/spool:ro
    - network_mode: so-elastic-net
