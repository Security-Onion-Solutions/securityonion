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

{% set interface = salt['pillar.get']('sensor:interface', 'bond0') %}

# Suricata

# Add Suricata Group
suricatagroup:
  group.present:
    - name: suricata
    - gid: 940

# Add ES user
suricata:
  user.present:
    - uid: 940
    - gid: 940
    - home: /opt/so/conf/suricata
    - createhome: False

suridir:
  file.directory:
    - name: /opt/so/conf/suricata
    - user: 940
    - group: 940

suriruledir:
  file.directory:
    - name: /opt/so/conf/suricata/rules
    - user: 940
    - group: 940
    - makedirs: True

surilogdir:
  file.directory:
    - name: /opt/so/log/suricata
    - user: 940
    - group: 939

surirulesync:
  file.recurse:
    - name: /opt/so/conf/suricata/rules/
    - source: salt://suricata/rules/
    - user: 940
    - group: 940

suriconfigsync:
  file.managed:
    - name: /opt/so/conf/suricata/suricata.yaml
    - source: salt://suricata/files/suricata.yaml
    - user: 940
    - group: 940

so-suricata:
  docker_container.running:
    - image: toosmooth/so-suricata:test2
    - privileged: True
    - environment:
      - interface={{ interface }}
    - binds:
      - /opt/so/conf/suricata/suricata.yaml:/usr/local/etc/suricata/suricata.yaml:ro
      - /opt/so/conf/suricata/rules:/usr/local/etc/suricata/rules:ro
      - /opt/so/log/suricata/:/usr/local/var/log/suricata/:rw
    - network_mode: host
