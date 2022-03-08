{% set HIGHLANDER = salt['pillar.get']('global:highlander', False) %}
include:
  - kibana

dashboard_saved_objects_template:
  file.managed:
    - name: /opt/so/conf/kibana/saved_objects.ndjson
    - source: salt://kibana/files/saved_objects.ndjson
    - user: 932
    - group: 939
    - show_changes: False

dashboard_saved_objects_changes:
  file.absent:
    - names:
      - /opt/so/state/kibana_saved_objects.txt
    - onchanges:
      - file: dashboard_saved_objects_template

so-kibana-dashboard-load:
  cmd.run:
    - name: /usr/sbin/so-kibana-config-load -i /opt/so/conf/kibana/saved_objects.ndjson
    - cwd: /opt/so
    - require:
      - sls: kibana
      - file: dashboard_saved_objects_template
{%- if HIGHLANDER %}
dashboard_saved_objects_template_hl:
  file.managed:
    - name: /opt/so/conf/kibana/hl.ndjson
    - source: salt://kibana/files/hl.ndjson
    - user: 932
    - group: 939
    - show_changes: False

dashboard_saved_objects_hl_changes:
  file.absent:
    - names:
      - /opt/so/state/kibana_hl.txt
    - onchanges:
      - file: dashboard_saved_objects_template_hl

so-kibana-dashboard-load_hl:
  cmd.run:
    - name: /usr/sbin/so-kibana-config-load -i /opt/so/conf/kibana/hl.ndjson
    - cwd: /opt/so
    - require:
      - sls: kibana
      - file: dashboard_saved_objects_template_hl
{%- endif %}
