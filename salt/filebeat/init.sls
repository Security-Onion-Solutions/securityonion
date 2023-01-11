# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'docker/docker.map.jinja' import DOCKER %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'filebeat/modules.map.jinja' import MODULESMERGED with context %}
{% from 'filebeat/modules.map.jinja' import MODULESENABLED with context %}
{% from 'filebeat/map.jinja' import FILEBEAT_EXTRA_HOSTS with context %}
{% set ES_INCLUDED_NODES = ['so-eval', 'so-standalone', 'so-managersearch', 'so-searchnode', 'so-heavynode', 'so-import'] %}

include:
  - ssl
#only include elastic state for certain nodes
{% if grains.role in ES_INCLUDED_NODES %}
  - elasticsearch
{% endif %}

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
filebeatconf:
  file.managed:
    - name: /opt/so/conf/filebeat/etc/filebeat.yml
    - source: salt://filebeat/etc/filebeat.yml
    - user: root
    - group: root
    - template: jinja
    - defaults:
        INPUTS: {{ salt['pillar.get']('filebeat:config:inputs', {}) }}
        OUTPUT: {{ salt['pillar.get']('filebeat:config:output', {}) }}
    - show_changes: False

# Filebeat module config file
filebeatmoduleconf:
  file.managed:
    - name: /opt/so/conf/filebeat/etc/module-setup.yml
    - source: salt://filebeat/etc/module-setup.yml
    - user: root
    - group: root
    - mode: 640
    - template: jinja
    - show_changes: False

merged_module_conf:
  file.managed:
    - name: /opt/so/conf/filebeat/modules/modules.yml
    - source: salt://filebeat/etc/module_config.yml.jinja
    - template: jinja
    - defaults:
        MODULES: {{ MODULESENABLED }}

so_module_conf_remove:
  file.absent:
    - name: /opt/so/conf/filebeat/modules/securityonion.yml

thirdyparty_module_conf_remove:
  file.absent:
    - name: /opt/so/conf/filebeat/modules/thirdparty.yml
    
so-filebeat:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-filebeat:{{ GLOBALS.so_version }}
    - hostname: so-filebeat
    - user: root
    - networks:
      - sosbridge:
        - ipv4_address: {{ DOCKER.containers['so-filebeat'].ip }}
    - extra_hosts: {{ FILEBEAT_EXTRA_HOSTS }}
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
      - /opt/so/log:/logs:ro
    - port_bindings:
        - 0.0.0.0:514:514/udp
        - 0.0.0.0:514:514/tcp
        - 0.0.0.0:5066:5066/tcp
{% for module in MODULESMERGED.modules.keys() %}
  {% for submodule in MODULESMERGED.modules[module] %}
    {% if MODULESMERGED.modules[module][submodule].enabled and MODULESMERGED.modules[module][submodule]["var.syslog_port"] is defined %}
        - {{ MODULESMERGED.modules[module][submodule].get("var.syslog_host", "0.0.0.0") }}:{{ MODULESMERGED.modules[module][submodule]["var.syslog_port"] }}:{{ MODULESMERGED.modules[module][submodule]["var.syslog_port"] }}/tcp
        - {{ MODULESMERGED.modules[module][submodule].get("var.syslog_host", "0.0.0.0") }}:{{ MODULESMERGED.modules[module][submodule]["var.syslog_port"] }}:{{ MODULESMERGED.modules[module][submodule]["var.syslog_port"] }}/udp
    {% endif %}
  {% endfor %}
{% endfor %}
    - watch:
      - file: filebeatconf
    - require:
      - file: filebeatconf
      - file: filebeatmoduleconf
      - file: filebeatmoduledir
      - x509: conf_filebeat_crt
      - x509: conf_filebeat_key
      - x509: trusttheca

{% if grains.role in ES_INCLUDED_NODES %}
run_module_setup:
  cmd.run:
    - name: /usr/sbin/so-filebeat-module-setup
    - require:
      - file: filebeatmoduleconf
      - docker_container: so-filebeat
    - onchanges:
      - docker_container: so-elasticsearch
{% endif %}

append_so-filebeat_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-filebeat

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
