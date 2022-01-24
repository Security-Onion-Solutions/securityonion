# Copyright 2014,2015,2016,2017,2018,2019,2020,2021,2022 Security Onion Solutions, LLC

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
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}

# Create the group
dstatsgroup:
  group.present:
    - name: domainstats
    - gid: 936

# Add user
domainstats:
  user.present:
    - uid: 936
    - gid: 936
    - home: /opt/so/conf/domainstats
    - createhome: False

# Create the log directory
dstatslogdir:
  file.directory:
    - name: /opt/so/log/domainstats
    - user: 936
    - group: 939
    - makedirs: True

so-domainstatsimage:
 cmd.run:
   - name: docker pull {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-domainstats:{{ VERSION }}

so-domainstats:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-domainstats:{{ VERSION }}
    - hostname: domainstats
    - name: so-domainstats
    - user: domainstats
    - binds:
      - /opt/so/log/domainstats:/var/log/domain_stats
    - require:
      - file: dstatslogdir
      - cmd: so-domainstatsimage

append_so-domainstats_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-domainstats

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
