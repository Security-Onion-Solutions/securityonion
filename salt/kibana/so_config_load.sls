include:
  - kibana
  - kibana.so_dashboard_load
  - kibana.so_securitySolution_load

config_saved_objects:
  file.managed:
    - name: /opt/so/conf/kibana/config_saved_objects.ndjson
    - source: salt://kibana/files/config_saved_objects.ndjson
    - user: 932
    - group: 939

so-kiba-config-load:
  cmd.run:
    - name: /usr/sbin/so-kibana-config-load -i /opt/so/conf/kibana/config_saved_objects.ndjson
    - cwd: /opt/so
    - require:
      - sls: kibana
      - file: config_saved_objects
