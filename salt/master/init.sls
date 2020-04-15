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
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}
{% set masterproxy = salt['pillar.get']('static:masterupdate', '0') %}

socore_own_saltstack:
  file.directory:
    - name: /opt/so/saltstack
    - user: socore
    - group: socore
    - recurse:
      - user
      - group

{% if masterproxy == 1 %}

# Create the directories for apt-cacher-ng
aptcacherconfdir:
  file.directory:
    - name: /opt/so/conf/aptcacher-ng/etc
    - user: 939
    - group: 939
    - makedirs: True

aptcachercachedir:
  file.directory:
    - name: /opt/so/conf/aptcacher-ng/cache
    - user: 939
    - group: 939
    - makedirs: True

aptcacherlogdir:
  file.directory:
    - name: /opt/so/log/aptcacher-ng
    - user: 939
    - group: 939
    - makedirs: true

# Copy the config

acngcopyconf:
  file.managed:
    - name: /opt/so/conf/aptcacher-ng/etc/acng.conf
    - source: salt://master/files/acng/acng.conf

# Install the apt-cacher-ng container
so-aptcacherng:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-acng:{{ VERSION }}
    - hostname: so-acng
    - port_bindings:
      - 0.0.0.0:3142:3142
    - binds:
      - /opt/so/conf/aptcacher-ng/cache:/var/cache/apt-cacher-ng:rw
      - /opt/so/log/aptcacher-ng:/var/log/apt-cacher-ng:rw
      - /opt/so/conf/aptcacher-ng/etc/acng.conf:/etc/apt-cacher-ng/acng.conf:ro

{% endif %}
