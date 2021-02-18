# Copyright 2014,2015,2016,2017,2018,2019,2020,2021 Security Onion Solutions, LLC
#
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

{% set MANAGER = salt['grains.get']('master') %}
{% set MANAGERIP = salt['pillar.get']('global:managerip', '') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set STRELKA_RULES = salt['pillar.get']('strelka:rules', '1') %}
{% set ENGINE = salt['pillar.get']('global:mdengine', '') %}

# Strelka config
strelkaconfdir:
  file.directory:
    - name: /opt/so/conf/strelka
    - user: 939
    - group: 939
    - makedirs: True

strelkarulesdir:
  file.directory:
    - name: /opt/so/conf/strelka/rules
    - user: 939
    - group: 939
    - makedirs: True

# Sync dynamic config to conf dir
strelkasync:
  file.recurse:
    - name: /opt/so/conf/strelka/
    - source: salt://strelka/files
    - user: 939
    - group: 939
    - template: jinja

{% if STRELKA_RULES == 1 %}

strelkarules:
  file.recurse:
    - name: /opt/so/conf/strelka/rules
    - source: salt://strelka/rules
    - user: 939
    - group: 939

{% if grains['role'] in ['so-eval','so-managersearch', 'so-manager', 'so-standalone', 'so-import'] %}
strelkarepos:
  file.managed:
    - name: /opt/so/saltstack/default/salt/strelka/rules/repos.txt
    - source: salt://strelka/rules/repos.txt.jinja
    - template: jinja

{% endif %}
{% endif %}

strelkadatadir:
   file.directory:
    - name: /nsm/strelka
    - user: 939
    - group: 939
    - makedirs: True

strelkalogdir:
  file.directory:
    - name: /nsm/strelka/log
    - user: 939
    - group: 939
    - makedirs: True

strelkaprocessed:
   file.directory:
    - name: /nsm/strelka/processed
    - user: 939
    - group: 939
    - makedirs: True

strelkaunprocessed:
   file.directory:
    - name: /nsm/strelka/unprocessed
    - user: 939
    - group: 939
    - makedirs: True

# Check to see if Strelka frontend port is available
strelkaportavailable:
    cmd.run:
      - name: netstat -utanp | grep ":57314" | grep -qv docker && PROCESS=$(netstat -utanp | grep ":57314" | uniq) && echo "Another process ($PROCESS) appears to be using port 57314.  Please terminate this process, or reboot to ensure a clean state so that Strelka can start properly." && exit 1 || exit 0

strelka_coordinator:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-redis:{{ VERSION }}
    - name: so-strelka-coordinator
    - entrypoint: redis-server --save "" --appendonly no
    - port_bindings:
      - 0.0.0.0:6380:6379

append_so-strelka-coordinator_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-coordinator

strelka_gatekeeper:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-redis:{{ VERSION }}
    - name: so-strelka-gatekeeper
    - entrypoint: redis-server --save "" --appendonly no --maxmemory-policy allkeys-lru
    - port_bindings:
      - 0.0.0.0:6381:6379

append_so-strelka-gatekeeper_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-gatekeeper

strelka_frontend:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-strelka-frontend:{{ VERSION }}
    - binds:
      - /opt/so/conf/strelka/frontend/:/etc/strelka/:ro
      - /nsm/strelka/log/:/var/log/strelka/:rw
    - privileged: True
    - name: so-strelka-frontend
    - command: strelka-frontend
    - port_bindings:
      - 0.0.0.0:57314:57314

append_so-strelka-frontend_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-frontend

strelka_backend:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-strelka-backend:{{ VERSION }}
    - binds:
      - /opt/so/conf/strelka/backend/:/etc/strelka/:ro
      - /opt/so/conf/strelka/rules/:/etc/yara/:ro
    - name: so-strelka-backend
    - command: strelka-backend
    - restart_policy: on-failure

append_so-strelka-backend_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-backend

strelka_manager:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-strelka-manager:{{ VERSION }}
    - binds:
      - /opt/so/conf/strelka/manager/:/etc/strelka/:ro
    - name: so-strelka-manager
    - command: strelka-manager

append_so-strelka-manager_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-manager

strelka_filestream:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-strelka-filestream:{{ VERSION }}
    - binds:
      - /opt/so/conf/strelka/filestream/:/etc/strelka/:ro
      - /nsm/strelka:/nsm/strelka
    - name: so-strelka-filestream
    - command: strelka-filestream

append_so-strelka-filestream_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-strelka-filestream

strelka_zeek_extracted_sync_old:
  cron.absent:
    - user: root
    - name: '[ -d /nsm/zeek/extracted/complete/ ] && mv /nsm/zeek/extracted/complete/* /nsm/strelka/ > /dev/null 2>&1'
    - minute: '*'

{% if ENGINE == "SURICATA" %}

strelka_suricata_extracted_sync:
  cron.present:
    - user: root
    - identifier: zeek-extracted-strelka-sync
    - name: '[ -d /nsm/suricata/extracted/ ] && find /nsm/suricata/extracted/* -not \( -path /nsm/suriextract/tmp -prune \) -type f -print0 | xargs -0 -I {} mv {} /tmp > /dev/null 2>&1'
    - minute: '*'

{% else %}
strelka_zeek_extracted_sync:
  cron.present:
    - user: root
    - identifier: zeek-extracted-strelka-sync
    - name: '[ -d /nsm/zeek/extracted/complete/ ] && mv /nsm/zeek/extracted/complete/* /nsm/strelka/unprocessed/ > /dev/null 2>&1'
    - minute: '*'

{% endif %}
{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
