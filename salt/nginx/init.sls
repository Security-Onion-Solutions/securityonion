{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'docker/docker.map.jinja' import DOCKER %}

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
    - show_changes: False

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
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-nginx:{{ GLOBALS.so_version }}
    - hostname: so-nginx
    - networks:
      - sobridge:
        - ipv4_address: {{ DOCKER.containers['so-nginx'].ip }}
    - extra_hosts:
      - {{ GLOBALS.manager }}:{{ GLOBALS.manager_ip }}
    - binds:
      - /opt/so/conf/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - /opt/so/log/nginx/:/var/log/nginx:rw
      - /opt/so/tmp/nginx/:/var/lib/nginx:rw
      - /opt/so/tmp/nginx/:/run:rw
      - /opt/so/saltstack/local/salt/elasticfleet/files/so_agent-installers/:/opt/socore/html/packages
  {% if grains.role in ['so-manager', 'so-managersearch', 'so-eval', 'so-standalone', 'so-import'] %}
      - /etc/pki/managerssl.crt:/etc/pki/nginx/server.crt:ro
      - /etc/pki/managerssl.key:/etc/pki/nginx/server.key:ro
      # ATT&CK Navigator binds
      - /opt/so/conf/navigator/navigator_config.json:/opt/socore/html/navigator/assets/config.json:ro
      - /opt/so/conf/navigator/nav_layer_playbook.json:/opt/socore/html/navigator/assets/playbook.json:ro
      - /opt/so/conf/navigator/enterprise-attack.json:/opt/socore/html/navigator/assets/enterprise-attack.json:ro
      - /opt/so/conf/navigator/pre-attack.json:/opt/socore/html/navigator/assets/pre-attack.json:ro
      - /nsm/repo:/opt/socore/html/repo:ro
  
  {% endif %}
    - cap_add: NET_BIND_SERVICE
    - port_bindings:
      {% for BINDING in DOCKER.containers['so-nginx'].port_bindings %}
      - {{ BINDING }}
      {% endfor %}
    - watch:
      - file: nginxconf
      - file: nginxconfdir
    - require:
      - file: nginxconf
  {% if grains.role in ['so-manager', 'so-managersearch', 'so-eval', 'so-standalone', 'so-import'] %}
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
