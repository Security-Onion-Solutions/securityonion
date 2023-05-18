# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls.split('.')[0] in allowed_states %}

{%   from 'docker/docker.map.jinja' import DOCKER %}
{%   from 'vars/globals.map.jinja' import GLOBALS %}
{%   set PLAYBOOKPASS = salt['pillar.get']('secrets:playbook_db') %}

include:
  - playbook.config
  - playbook.sostatus

{%   if PLAYBOOKPASS == None %}

playbook_password_none:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "Playbook MySQL Password Error - Not Starting Playbook"

{%   else %}

so-playbook:
  docker_container.running:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-playbook:{{ GLOBALS.so_version }}
    - hostname: playbook
    - name: so-playbook
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-playbook'].ip }}
    - binds:
      - /opt/so/log/playbook:/playbook/log:rw
      {% if DOCKER.containers['so-playbook'].custom_bind_mounts %}
        {% for BIND in DOCKER.containers['so-playbook'].custom_bind_mounts %}
      - {{ BIND }}
        {% endfor %}
      {% endif %}
    - extra_hosts:
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
      {% if DOCKER.containers['so-playbook'].extra_hosts %}
        {% for XTRAHOST in DOCKER.containers['so-kratos'].extra_hosts %}
      - {{ XTRAHOST }}
        {% endfor %}
      {% endif %}
    - environment:
      - REDMINE_DB_MYSQL={{ GLOBALS.manager }}
      - REDMINE_DB_DATABASE=playbook
      - REDMINE_DB_USERNAME=playbookdbuser
      - REDMINE_DB_PASSWORD={{ PLAYBOOKPASS }}
      {% if DOCKER.containers['so-kratos'].extra_env %}
        {% for XTRAENV in DOCKER.containers['so-kratos'].extra_env %}
      - {{ XTRAENV }}
        {% enfor %}
      {% endif %}
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-playbook'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}

delete_so-playbook_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-playbook$

so-playbook-sync_cron:
  cron.present:
    - name: /usr/sbin/so-playbook-sync > /opt/so/log/playbook/sync.log 2>&1
    - identifier: so-playbook-sync_cron
    - user: root
    - minute: '*/5'

so-playbook-ruleupdate_cron:
  cron.present:
    - name: /usr/sbin/so-playbook-ruleupdate > /opt/so/log/playbook/update.log 2>&1
    - identifier: so-playbook-ruleupdate_cron
    - user: root
    - minute: '1'
    - hour: '6'

{%   endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
