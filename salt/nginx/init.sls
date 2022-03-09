{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set FLEETMANAGER = salt['pillar.get']('global:fleet_manager', False) %}
{% set FLEETNODE = salt['pillar.get']('global:fleet_node', False) %}
{% set MANAGER = salt['grains.get']('master') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set ISAIRGAP = salt['pillar.get']('global:airgap') %}

include:
  - ssl

# Drop the correct nginx config based on role
nginxconfdir:
  file.directory:
    - name: /opt/so/conf/nginx/html
    - user: 939
    - group: 939
    - makedirs: True

nginxhtml:
  file.recurse:
    - name: /opt/so/conf/nginx/html
    - source: salt://nginx/html/
    - user: 939
    - group: 939

nginxconf:
  file.managed:
    - name: /opt/so/conf/nginx/nginx.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://nginx/etc/nginx.conf

nginxlogdir:
  file.directory:
    - name: /opt/so/log/nginx/
    - user: 939
    - group: 939
    - makedirs: True

nginxtmp:
  file.directory:
    - name: /opt/so/tmp/nginx/tmp
    - user: 939
    - group: 939
    - makedirs: True

navigatorconfig:
  file.managed:
    - name: /opt/so/conf/navigator/navigator_config.json
    - source: salt://nginx/files/navigator_config.json
    - user: 939
    - group: 939
    - makedirs: True
    - template: jinja

navigatordefaultlayer:
  file.managed:
    - name: /opt/so/conf/navigator/nav_layer_playbook.json
    - source: salt://nginx/files/nav_layer_playbook.json
    - user: 939
    - group: 939
    - makedirs: True
    - replace: False
    - template: jinja

navigatorpreattack:
  file.managed:
    - name: /opt/so/conf/navigator/pre-attack.json
    - source: salt://nginx/files/pre-attack.json
    - user: 939
    - group: 939
    - makedirs: True
    - replace: False

navigatorenterpriseattack:
  file.managed:
    - name: /opt/so/conf/navigator/enterprise-attack.json
    - source: salt://nginx/files/enterprise-attack.json
    - user: 939
    - group: 939
    - makedirs: True
    - replace: False

so-nginx:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-nginx:{{ VERSION }}
    - hostname: so-nginx
    - binds:
      - /opt/so/conf/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - /opt/so/log/nginx/:/var/log/nginx:rw
      - /opt/so/tmp/nginx/:/var/lib/nginx:rw
      - /opt/so/tmp/nginx/:/run:rw
      - /opt/so/conf/fleet/packages:/opt/socore/html/packages
  {% if grains.role in ['so-manager', 'so-managersearch', 'so-eval', 'so-standalone', 'so-import', 'so-fleet'] %}
      - /etc/pki/managerssl.crt:/etc/pki/nginx/server.crt:ro
      - /etc/pki/managerssl.key:/etc/pki/nginx/server.key:ro
      # ATT&CK Navigator binds
      - /opt/so/conf/navigator/navigator_config.json:/opt/socore/html/navigator/assets/config.json:ro
      - /opt/so/conf/navigator/nav_layer_playbook.json:/opt/socore/html/navigator/assets/playbook.json:ro
      - /opt/so/conf/navigator/enterprise-attack.json:/opt/socore/html/navigator/assets/enterprise-attack.json:ro
      - /opt/so/conf/navigator/pre-attack.json:/opt/socore/html/navigator/assets/pre-attack.json:ro
  {% endif %}
  {% if ISAIRGAP is sameas true %}
      - /nsm/repo:/opt/socore/html/repo:ro
  {% endif %}
    - cap_add: NET_BIND_SERVICE
    - port_bindings:
      - 80:80
      - 443:443
  {% if ISAIRGAP is sameas true %}
      - 7788:7788
  {% endif %}
  {%- if FLEETMANAGER or FLEETNODE %}
      - 8090:8090
  {%- endif %}
    - watch:
      - file: nginxconf
      - file: nginxconfdir
    - require:
      - file: nginxconf
  {% if grains.role in ['so-manager', 'so-managersearch', 'so-eval', 'so-standalone', 'so-import', 'so-fleet'] %}
      - x509: managerssl_key
      - x509: managerssl_crt
      - file: navigatorconfig
      - file: navigatordefaultlayer
  {% endif %}

append_so-nginx_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-nginx

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
