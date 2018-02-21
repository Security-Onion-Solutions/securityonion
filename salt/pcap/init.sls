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

# PCAP Section

stenoconfdir:
  file.directory:
    - name: /opt/so/conf/steno
    - user: 941
    - group: 939
    - makedirs: True

stenoconf:
  file.managed:
    - name: /opt/so/conf/steno/config
    - source: salt://pcap/files/config
    - user: 941
    - group: 939
    - template: jinja

pcapdir:
  file.directory:
    - name: /nsm/pcap
    - user: 941
    - group: 939
    - makedirs: True

pcapindexdir:
  file.directory:
    - name: /nsm/pcapindex
    - user: 941
    - group: 939
    - makedirs: True

so-steno:
  dockerng.running:
    - image: toosmooth/so-steno:test2
    - network_mode: host
    - user: 941
    - priviledged: true
    - binds:
      - /opt/so/conf/stenographer/certs:/etc/stenographer/certs:rw
      - /opt/so/conf/stenographer/config:/etc/stenographer/config:ro
      - /nsm/pcap:/nsm/pcap:rw
      - /nsm/pcapindex:/nsm/pcapindex:rw
