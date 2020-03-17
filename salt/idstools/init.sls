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
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.1.4') %}
{% set MASTER = salt['grains.get']('master') %}
# IDSTools Setup
idstoolsdir:
  file.directory:
    - name: /opt/so/conf/idstools/etc
    - user: 939
    - group: 939
    - makedirs: True

idstoolslogdir:
  file.directory:
    - name: /opt/so/log/idstools
    - user: 939
    - group: 939
    - makedirs: True

idstoolsetcsync:
  file.recurse:
    - name: /opt/so/conf/idstools/etc
    - source: salt://idstools/etc
    - user: 939
    - group: 939
    - template: jinja

so-ruleupdatecron:
  cron.present:
    - name: /usr/sbin/so-rule-update.sh > /opt/so/log/idstools/download.log
    - user: root
    - minute: '1'
    - hour: '7'

rulesdir:
  file.directory:
    - name: /opt/so/rules/nids
    - user: 939
    - group: 939
    - makedirs: True

synclocalnidsrules:
  file.managed:
    - name: /opt/so/rules/nids/local.rules
    - source: salt://idstools/localrules/local.rules
    - user: 939
    - group: 939

ruleslink:
  file.symlink:
    - name: /opt/so/saltstack/salt/suricata/rules
    - target: /opt/so/rules/nids

so-idstools:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-idstools:{{ VERSION }}
    - hostname: so-idstools
    - user: socore
    - binds:
      - /opt/so/conf/idstools/etc:/opt/so/idstools/etc:ro
      - /opt/so/rules/nids:/opt/so/rules/nids:rw
