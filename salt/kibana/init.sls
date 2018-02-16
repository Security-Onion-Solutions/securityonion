# Add ES Group
kibanasearchgroup:
  group.present:
    - name: elasticsearch
    - gid: 932

# Add ES user
kibanasearch:
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

kibanalogdir:
  file.directory:
    - name: /opt/so/conf/kibana/customdashboards
    - user: 932
    - group: 939
    - makedirs: True

# Start the kibana docker
so-kibana:
  docker_container.running:
    - image: toosmooth/so-kibana:test2
    - hostname: kibana
    - user: kibana
    - environment:
      - KIBANA_DEFAULTAPPID=$KIBANA_DEFAULTAPPID
    - binds:
      - /opt/so/conf/kibana/:/usr/share/kibana/config/:ro
      - /opt/so/log/kibana:/var/log/kibana:rw
    - network_mode: so-elastic-net
    - port_bindings:
      - 127.0.01:5601:5601
