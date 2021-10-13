include:
  - kibana

dashboard_saved_objects_template:
  file.managed:
    - name: /opt/so/conf/kibana/saved_objects.ndjson.template
    - source: salt://kibana/files/saved_objects.ndjson
    - user: 932
    - group: 939

so-kiba-dashboard-load:
  cmd.run:
    - name: /usr/sbin/so-kibana-config-load /opt/so/conf/kibana/saved_objects.ndjson.template
    - cwd: /opt/so
    - require:
      - sls: kibana
      - file: dashboard_saved_objects_template
