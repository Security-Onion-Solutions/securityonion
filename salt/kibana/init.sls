{% set master = salt['grains.get']('master') %}

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

so-kibanaimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false docker.io/soshybridhunter/so-kibana:HH1.1.1

# Start the kibana docker
so-kibana:
  docker_container.running:
    - require:
      - so-kibanaimage
    - image: docker.io/soshybridhunter/so-kibana:HH1.1.1
    - hostname: kibana
    - user: kibana
    - environment:
      - KIBANA_DEFAULTAPPID=dashboard/94b52620-342a-11e7-9d52-4f090484f59e
      - ELASTICSEARCH_HOST={{ master }}
      - ELASTICSEARCH_PORT=9200
      - MASTER={{ master }}
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
    - source: salt://kibana/bin/so-kibana-config-load

# Keep the setting correct
#KibanaHappy:
#  cmd.script:
#    - shell: /bin/bash
#    - runas: socore
#    - source: salt://kibana/bin/keepkibanahappy.sh
#    - template: jinja
