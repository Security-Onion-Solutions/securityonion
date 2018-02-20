

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
    - name: /opt/so/conf/kibana
    - user: 932
    - group: 939
    - makedirs: True

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

# File.Recurse for custom saved dashboards

# Start the kibana docker
so-kibana:
  docker_container.running:
    - image: toosmooth/so-kibana:test2
    - hostname: kibana
    - user: kibana
    - environment:
      - KIBANA_DEFAULTAPPID=dashboard/94b52620-342a-11e7-9d52-4f090484f59e
      - ELASTICSEARCH_HOST=elasticsearch
      - ELASTICSEARCH_PORT=9200
    - binds:
      - /opt/so/conf/kibana/:/usr/share/kibana/config/:ro
      - /opt/so/log/kibana:/var/log/kibana:rw
      - /opt/so/conf/kibana/custdashboards/:/usr/share/kibana/custdashboards/:ro
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
    - network_mode: so-elastic-net
    - port_bindings:
      - 127.0.0.1:5601:5601
