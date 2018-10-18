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

# PulledProk Setup
ppdir:
  file.directory:
    - name: /opt/so/pulledpork/etc
    - user: 939
    - group: 939
    - makedirs: True

ppetcsync:
  file.recurse:
    - name: /opt/so/pulledpork/etc
    - source: salt://pulledpork/etc
    - user: 939
    - group: 939
    - template: jinja

rulesdir:
  file.directory:
    - name: /opt/so/rules/nids
    - user: 939
    - group: 939
    - makedirs: True

ruleslink:
  file.symlink:
    - name: /opt/so/saltstack/salt/pulledpork/rules
    - target: /opt/so/rules/nids

toosmooth/so-pulledpork:test2:
  docker_image.present

so-pulledpork:
  docker_container.running:
    - image: toosmooth/so-pulledpork:test2
    - hostname: so-pulledpork
    - user: socore
    - binds:
      - /opt/so/pulledpork/etc:/opt/pulledpork/etc:ro
      - /opt/so/rules/nids:/opt/so/rules/nids:rw
    - network_mode: so-elastic-net
