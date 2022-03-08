include:
  - kibana

config_saved_objects:
  file.managed:
    - name: /opt/so/conf/kibana/config_saved_objects.ndjson
    - source: salt://kibana/files/config_saved_objects.ndjson
    - user: 932
    - group: 939

config_saved_objects_changes:
  file.absent:
    - names:
      - /opt/so/state/kibana_config_saved_objects.txt
    - onchanges:
      - file: config_saved_objects

so-kibana-config-load:
  cmd.run:
    - name: /usr/sbin/so-kibana-config-load -i /opt/so/conf/kibana/config_saved_objects.ndjson
    - cwd: /opt/so
    - require:
      - sls: kibana
      - file: config_saved_objects
