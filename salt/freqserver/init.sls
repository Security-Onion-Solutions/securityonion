# Copyright 2014,2015,2016,2017,2018,2019,2020 Security Onion Solutions, LLC

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
{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'freqserver' in top_states %}

{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}

# Create the user
fservergroup:
  group.present:
    - name: freqserver
    - gid: 935

# Add ES user
freqserver:
  user.present:
    - uid: 935
    - gid: 935
    - home: /opt/so/conf/freqserver
    - createhome: False

# Create the log directory
freqlogdir:
  file.directory:
    - name: /opt/so/log/freq_server
    - user: 935
    - group: 935
    - makedirs: True

so-freqimage:
 cmd.run:
   - name: docker pull {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-freqserver:{{ VERSION }}

so-freq:
  docker_container.running:
    - require:
      - so-freqimage
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-freqserver:{{ VERSION }}
    - hostname: freqserver
    - name: so-freqserver
    - user: freqserver
    - binds:
      - /opt/so/log/freq_server:/var/log/freq_server:rw

append_so-freq_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-freq

{% else %}

freqserver_state_not_allowed:
  test.fail_without_changes:
    - name: freqserver_state_not_allowed

{% endif %}

