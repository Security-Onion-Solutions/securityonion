{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'kibana' in top_states %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set FEATURES = salt['pillar.get']('elastic:features', False) %}
{%- if FEATURES is sameas true %}
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

kibanabin:
  file.managed:
    - name: /usr/sbin/so-kibana-config-load
    - source: salt://kibana/bin/so-kibana-config-load
    - mode: 755
    - template: jinja

# Start the kibana docker
so-kibana:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-kibana:{{ VERSION }}{{ FEATURES }}
    - hostname: kibana
    - user: kibana
    - environment:
      - ELASTICSEARCH_HOST={{ MANAGER }}
      - ELASTICSEARCH_PORT=9200
      - MANAGER={{ MANAGER }}
    - binds:
      - /opt/so/conf/kibana/etc:/usr/share/kibana/config:rw
      - /opt/so/log/kibana:/var/log/kibana:rw
      - /opt/so/conf/kibana/customdashboards:/usr/share/kibana/custdashboards:ro
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
    - port_bindings:
      - 0.0.0.0:5601:5601

kibanadashtemplate:
  file.managed:
    - name: /opt/so/conf/kibana/saved_objects.ndjson.template
    - source: salt://kibana/files/saved_objects.ndjson
    - user: 932
    - group: 939

wait_for_kibana:
  module.run:
    - http.wait_for_successful_query:
      - url: "http://{{MANAGER}}:5601/api/saved_objects/_find?type=config"
      - wait_for: 180
    - onchanges:
      - file: kibanadashtemplate

so-kibana-config-load:
  cmd.run:
    - name: /usr/sbin/so-kibana-config-load
    - cwd: /opt/so
    - onchanges:
      - wait_for_kibana


# Keep the setting correct
#KibanaHappy:
#  cmd.script:
#    - shell: /bin/bash
#    - runas: socore
#    - source: salt://kibana/bin/keepkibanahappy.sh
#    - template: jinja

{% else %}

kibana_state_not_allowed:
  test.fail_without_changes:
    - name: kibana_state_not_allowed

{% endif %}