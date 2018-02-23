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

# Suricata
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

surirulesync:
  file.recurse:
    - name: /opt/so

suriconfigsync:
  file.recurse:
    - name: /opt/so/conf/suricata
    - source: salt://pulledpork/rules
    - user: 940
    - group: 940

so-suricata:
  docker_container.running:
    - image: toosmooth/so-suricata:test2
    - hostname: so-suricata
    - user: suricata
    - priviledged: True
    - binds:
      - /opt/so/suricata/conf/rules:/usr/local/etc/suricata/rules:ro
      - /opt/so/rules/nids:/opt/so/rules/nids:rw
    - network_mode: host
