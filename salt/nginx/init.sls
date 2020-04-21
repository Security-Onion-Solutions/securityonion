{% set FLEETMASTER = salt['pillar.get']('static:fleet_master', False) %}
{% set FLEETNODE = salt['pillar.get']('static:fleet_node', False) %}
{% set MASTER = salt['grains.get']('master') %}
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}

# Drop the correct nginx config based on role
nginxconfdir:
  file.directory:
    - name: /opt/so/conf/nginx
    - user: 939
    - group: 939
    - makedirs: True

nginxconf:
  file.managed:
    - name: /opt/so/conf/nginx/nginx.conf
    - user: 939
    - group: 939
    - template: jinja
    - source: salt://nginx/etc/nginx.conf.{{ grains.role }}

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

so-core:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-core:{{ VERSION }}
    - hostname: so-core
    - user: socore
    - binds:
      - /opt/so:/opt/so:rw
      - /opt/so/conf/nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - /opt/so/log/nginx/:/var/log/nginx:rw
      - /opt/so/tmp/nginx/:/var/lib/nginx:rw
      - /opt/so/tmp/nginx/:/run:rw
      - /etc/pki/masterssl.crt:/etc/pki/nginx/server.crt:ro
      - /etc/pki/masterssl.key:/etc/pki/nginx/server.key:ro
      - /opt/so/conf/fleet/packages:/opt/socore/html/packages
    - cap_add: NET_BIND_SERVICE
    - port_bindings:
      - 80:80
      - 443:443
    {%- if FLEETMASTER or FLEETNODE %}
      - 8090:8090
    {%- endif %}
    - watch:
      - file: nginxconf