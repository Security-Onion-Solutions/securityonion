# Copyright 2014,2015,2016,2017,2018,2019,2020,2021 Security Onion Solutions, LLC
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
{% set LOCALHOSTNAME = salt['grains.get']('host') %}
{% set MAININT = salt['pillar.get']('host:mainint') %}
{% set LOCALHOSTIP = salt['grains.get']('ip_interfaces').get(MAININT)[0] %}
{% set MANAGER = salt['grains.get']('master') %}
{% set MANAGERIP = salt['pillar.get']('global:managerip', '') %}
{% from 'filebeat/map.jinja' import THIRDPARTY with context %}
{% from 'filebeat/map.jinja' import SO with context %}


filebeatetcdir:
  file.directory:
    - name: /opt/so/conf/filebeat/etc
    - user: 939
    - group: 939
    - makedirs: True

filebeatmoduledir:
  file.directory:
    - name: /opt/so/conf/filebeat/modules
    - user: root
    - group: root
    - makedirs: True

filebeatlogdir:
  file.directory:
    - name: /opt/so/log/filebeat
    - user: 939
    - group: 939
    - makedirs: True

filebeatpkidir:
  file.directory:
    - name: /opt/so/conf/filebeat/etc/pki
    - user: 939
    - group: 939
    - makedirs: True
fileregistrydir:
  file.directory:
    - name: /opt/so/conf/filebeat/registry
    - user: 939
    - group: 939
    - makedirs: True

# This needs to be owned by root
filebeatconfsync:
  file.managed:
    - name: /opt/so/conf/filebeat/etc/filebeat.yml
    - source: salt://filebeat/etc/filebeat.yml
    - user: root
    - group: root
    - template: jinja
    - defaults:
        INPUTS: {{ salt['pillar.get']('filebeat:config:inputs', {}) }}
        OUTPUT: {{ salt['pillar.get']('filebeat:config:output', {}) }}

# Filebeat module config file
filebeatmoduleconfsync:
  file.managed:
    - name: /opt/so/conf/filebeat/etc/module-setup.yml
    - source: salt://filebeat/etc/module-setup.yml
    - user: root
    - group: root
    - template: jinja

sodefaults_module_conf:
  file.managed:
    - name: /opt/so/conf/filebeat/modules/securityonion.yml
    - source: salt://filebeat/etc/module_config.yml.jinja
    - template: jinja
    - defaults:
        MODULES: {{ SO }}

thirdparty_module_conf:
  file.managed:
    - name: /opt/so/conf/filebeat/modules/thirdparty.yml
    - source: salt://filebeat/etc/module_config.yml.jinja
    - template: jinja
    - defaults:
        MODULES: {{ THIRDPARTY }}
    
so-filebeat:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-filebeat:{{ VERSION }}
    - hostname: so-filebeat
    - user: root
    - extra_hosts: {{ MANAGER }}:{{ MANAGERIP }},{{ LOCALHOSTNAME }}:{{ LOCALHOSTIP }}
    - binds:
      - /nsm:/nsm:ro
      - /opt/so/log/filebeat:/usr/share/filebeat/logs:rw
      - /opt/so/conf/filebeat/etc/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /opt/so/conf/filebeat/etc/module-setup.yml:/usr/share/filebeat/module-setup.yml:ro
      - /nsm/wazuh/logs/alerts:/wazuh/alerts:ro
      - /nsm/wazuh/logs/archives:/wazuh/archives:ro
      - /opt/so/conf/filebeat/modules:/usr/share/filebeat/modules.d
      - /opt/so/conf/filebeat/etc/pki/filebeat.crt:/usr/share/filebeat/filebeat.crt:ro
      - /opt/so/conf/filebeat/etc/pki/filebeat.key:/usr/share/filebeat/filebeat.key:ro
      - /opt/so/conf/filebeat/registry:/usr/share/filebeat/data/registry:rw
      - /etc/ssl/certs/intca.crt:/usr/share/filebeat/intraca.crt:ro
    - port_bindings:
        - 0.0.0.0:514:514/udp
        - 0.0.0.0:514:514/tcp
        - 0.0.0.0:5066:5066/tcp
{% for module in THIRDPARTY.modules.keys() %}
  {% for submodule in THIRDPARTY.modules[module] %}
    {% if THIRDPARTY.modules[module][submodule].enabled %}
        - {{ THIRDPARTY.modules[module][submodule].get("var.syslog_host", "0.0.0.0") }}:{{ THIRDPARTY.modules[module][submodule]["var.syslog_port"] }}:{{ THIRDPARTY.modules[module][submodule]["var.syslog_port"] }}/{{ THIRDPARTY.modules[module][submodule]["var.input"] }}
    {% endif %}
  {% endfor %}
{% endfor %}
    - watch:
      - file: /opt/so/conf/filebeat/etc/filebeat.yml

append_so-filebeat_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-filebeat

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
