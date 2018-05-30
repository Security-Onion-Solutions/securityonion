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

{% set masterproxy = salt['pillar.get']('static:masterupdate', '0') %}

{% if masterproxy == 1 %}

# Create the directories for apt-cacher-ng
aptcacherconfdir:
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
# Install the apt-cacher-ng container - TODO Create a so-docker for it
so-aptcacherng:
  docker_container.running:
    - image: deployable/acng:latest-us
    - hostname: so-aptcacherng
    - port_bindings:
      - 0.0.0.0:3142:3142
    - binds:
      - /opt/so/conf/aptcacher-ng/cache:/var/cache/apt-cacher-ng:rw


# Create the config directory for the docker registry
# Copy the config
# Install the registry container

{% endif %}
