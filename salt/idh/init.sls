
# Copyright 2014-2022 Security Onion Solutions, LLC
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

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}

include:
  - idh.openssh.config

# IDH State

# Create a config directory
temp:
  file.directory:
    - name: /opt/so/conf/idh
    - user: 939
    - group: 939
    - makedirs: True

# Create a log directory
configdir:
  file.directory:
    - name: /nsm/idh
    - user: 939
    - group: 939
    - makedirs: True

{% from 'idh/opencanary_config.map.jinja' import OPENCANARYCONFIG with context %}
opencanary_config:
  file.managed:
    - name: /opt/so/conf/idh/opencanary.conf
    - source: salt://idh/idh.conf.jinja
    - template: jinja
    - defaults:
        OPENCANARYCONFIG: {{ OPENCANARYCONFIG }}

so-idh:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-idh:{{ VERSION }}
    - name: so-idh
    - detach: True
    - network_mode: host
    - binds:
      - /nsm/idh:/var/tmp:rw
      - /opt/so/conf/idh/opencanary.conf:/etc/opencanaryd/opencanary.conf:ro
    - watch:
      - file: opencanary_config
    - require:
      - file: opencanary_config

append_so-idh_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-idh

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
