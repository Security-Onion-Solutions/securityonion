{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}

socdir:
  file.directory:
    - name: /opt/so/conf/soc
    - user: 939
    - group: 939
    - makedirs: True

socdatadir:
  file.directory:
    - name: /nsm/soc/jobs
    - user: 939
    - group: 939
    - makedirs: True

soclogdir:
  file.directory:
    - name: /opt/so/log/soc
    - user: 939
    - group: 939
    - makedirs: True

socactions:
  file.managed:
    - name: /opt/so/conf/soc/menu.actions.json
    - source: salt://soc/files/soc/menu.actions.json
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

socconfig:
  file.managed:
    - name: /opt/so/conf/soc/soc.json
    - source: salt://soc/files/soc/soc.json
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja
    - show_changes: False

socmotd:
  file.managed:
    - name: /opt/so/conf/soc/motd.md
    - source: salt://soc/files/soc/motd.md
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

socbanner:
  file.managed:
    - name: /opt/so/conf/soc/banner.md
    - source: salt://soc/files/soc/banner.md
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

soccustom:
  file.managed:
    - name: /opt/so/conf/soc/custom.js
    - source: salt://soc/files/soc/custom.js
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

soccustomroles:
  file.managed:
    - name: /opt/so/conf/soc/custom_roles
    - source: salt://soc/files/soc/custom_roles
    - user: 939
    - group: 939
    - mode: 600
    - template: jinja

socusersroles:
  file.exists:
    - name: /opt/so/conf/soc/soc_users_roles

# we dont want this added too early in setup, so we add the onlyif to verify 'startup_states: highstate'
# is in the minion config. That line is added before the final highstate during setup
sosyncusers:
  cron.present:
    - user: root
    - name: 'PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/root/bin /usr/sbin/so-user sync &>> /opt/so/log/soc/sync.log'
    - onlyif: "grep 'startup_states: highstate' /etc/salt/minion"

so-soc:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-soc:{{ VERSION }}
    - hostname: soc
    - name: so-soc
    - binds:
      - /nsm/soc/jobs:/opt/sensoroni/jobs:rw
      - /opt/so/log/soc/:/opt/sensoroni/logs/:rw
      - /opt/so/conf/soc/soc.json:/opt/sensoroni/sensoroni.json:ro
      - /opt/so/conf/soc/motd.md:/opt/sensoroni/html/motd.md:ro
      - /opt/so/conf/soc/banner.md:/opt/sensoroni/html/login/banner.md:ro
      - /opt/so/conf/soc/custom.js:/opt/sensoroni/html/js/custom.js:ro
      - /opt/so/conf/soc/custom_roles:/opt/sensoroni/rbac/custom_roles:ro
      - /opt/so/conf/soc/soc_users_roles:/opt/sensoroni/rbac/users_roles:rw
    {%- if salt['pillar.get']('nodestab', {}) %}
    - extra_hosts:
      {%- for SN, SNDATA in salt['pillar.get']('nodestab', {}).items() %}
      - {{ SN.split('_')|first }}:{{ SNDATA.ip }}
      {%- endfor %}
      {%- endif %}
    - port_bindings:
      - 0.0.0.0:9822:9822
    - watch:
      - file: /opt/so/conf/soc/*
    - require:
      - file: socdatadir
      - file: soclogdir
      - file: socconfig
      - file: socmotd
      - file: socbanner
      - file: soccustom
      - file: soccustomroles
      - file: socusersroles

append_so-soc_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-soc

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
