include:
  - kibana

securitySolution_saved_objects:
  file.managed:
    - name: /opt/so/conf/kibana/securitySolution_saved_objects.ndjson
    - source: salt://kibana/files/securitySolution_saved_objects.ndjson
    - user: 932
    - group: 939

so-kiba-securitySolution_saved_objects-load:
  cmd.run:
    - name: /usr/sbin/so-kibana-config-load /opt/so/conf/kibana/securitySolution_saved_objects.ndjson
    - cwd: /opt/so
    - require:
      - sls: kibana
      - file: securitySolution_saved_objects
