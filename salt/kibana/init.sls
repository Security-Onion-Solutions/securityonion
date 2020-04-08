{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}
{% set FEATURES = salt['pillar.get']('elastic:features', False) %}
{% if FEATURES %}
  {% set FEATURES = "-features" %}
{% else %}
  {% set FEATURES = '' %}
{% endif %}

# Add ES Group
kibanasearchgroup:
  group.present:
    - name: kibana
    - gid: 932

# Add ES user
kibana:
  user.present:
    - uid: 932
    - gid: 932
    - home: /opt/so/conf/kibana
    - createhome: False

# Drop the correct nginx config based on role

kibanaconfdir:
  file.directory:
    - name: /opt/so/conf/kibana/etc
    - user: 932
    - group: 939
    - makedirs: True

synckibanaconfig:
  file.recurse:
    - name: /opt/so/conf/kibana/etc
    - source: salt://kibana/etc
    - user: 932
    - group: 939
    - template: jinja

kibanalogdir:
  file.directory:
    - name: /opt/so/log/kibana
    - user: 932
    - group: 939
    - makedirs: True

kibanacustdashdir:
  file.directory:
    - name: /opt/so/conf/kibana/customdashboards
    - user: 932
    - group: 939
    - makedirs: True

synckibanacustom:
  file.recurse:
    - name: /opt/so/conf/kibana/customdashboards
    - source: salt://kibana/custom
    - user: 932
    - group: 939

# File.Recurse for custom saved dashboards

# Start the kibana docker
so-kibana:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-kibana:{{ VERSION }}{{ FEATURES }}
    - hostname: kibana
    - user: kibana
    - environment:
      - ELASTICSEARCH_HOST={{ MASTER }}
      - ELASTICSEARCH_PORT=9200
      - MASTER={{ MASTER }}
    - binds:
      - /opt/so/conf/kibana/etc:/usr/share/kibana/config:rw
      - /opt/so/log/kibana:/var/log/kibana:rw
      - /opt/so/conf/kibana/customdashboards:/usr/share/kibana/custdashboards:ro
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
    - port_bindings:
      - 0.0.0.0:5601:5601

so-kibana-config-load:
  cmd.script:
    - shell: /bin/bash
    - runas: socore
    - cwd: /opt/so
    - source: salt://kibana/bin/so-kibana-config-load
    - template: jinja

# Keep the setting correct
#KibanaHappy:
#  cmd.script:
#    - shell: /bin/bash
#    - runas: socore
#    - source: salt://kibana/bin/keepkibanahappy.sh
#    - template: jinja
