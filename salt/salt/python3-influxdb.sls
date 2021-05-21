{% from "salt/map.jinja" import SALT_STATE_CODE_PATH with context %}
{% from "salt/map.jinja" import SALT_MODULE_CODE_PATH with context %}
{% from "salt/map.jinja" import PYTHON3INFLUX with context %}
{% from "salt/map.jinja" import PYTHON3INFLUXDEPS with context %}
{% from "salt/map.jinja" import PYTHONINSTALLER with context %}

include:
  - salt.helper-packages

python3_influxdb_dependencies:
  {{PYTHONINSTALLER}}.installed:
    - pkgs: {{ PYTHON3INFLUXDEPS }}

python3_influxdb:
  {{PYTHONINSTALLER}}.installed:
    - name: {{ PYTHON3INFLUX }}

# We circumvent the file.patch state putting ERROR in the log by using the unless and file.touch below
# https://github.com/saltstack/salt/pull/47010 and https://github.com/saltstack/salt/issues/52329

#https://github.com/saltstack/salt/issues/59766
influxdb_continuous_query.present_patch:
  file.patch:
    - name: {{ SALT_STATE_CODE_PATH }}/influxdb_continuous_query.py
    - source: salt://salt/files/influxdb_continuous_query.py.patch
    - require:
      - {{PYTHONINSTALLER}}: python3_influxdb
      - pkg: patch_package
    - unless: ls /opt/so/state/influxdb_continuous_query.py.patched

influxdb_continuous_query.py.patched:
  file.touch:
    - name: /opt/so/state/influxdb_continuous_query.py.patched
    - onchanges:
      - file: influxdb_continuous_query.present_patch

#https://github.com/saltstack/salt/issues/59761
influxdb_retention_policy.present_patch:
  file.patch:
    - name: {{ SALT_STATE_CODE_PATH }}/influxdb_retention_policy.py
    - source: salt://salt/files/influxdb_retention_policy.py.patch
    - require:
      - {{PYTHONINSTALLER}}: python3_influxdb
      - pkg: patch_package
    - unless: ls /opt/so/state/influxdb_retention_policy.py.patched

influxdb_retention_policy.py.patched:
  file.touch:
    - name: /opt/so/state/influxdb_retention_policy.py.patched
    - onchanges:
      - file: influxdb_retention_policy.present_patch

# We should be able to set reload_modules: True in this state in order to tell salt to reload its python modules due to us possibly installing
# and possibly modifying modules in this state. This is bugged according to https://github.com/saltstack/salt/issues/24925
influxdbmod.py_shard_duration_patch:
  file.patch:
    - name: {{ SALT_MODULE_CODE_PATH }}/influxdbmod.py
    - source: salt://salt/files/influxdbmod.py.patch
    - require:
      - {{PYTHONINSTALLER}}: python3_influxdb
      - pkg: patch_package
    - unless: ls /opt/so/state/influxdbmod.py.patched

influxdbmod.py.patched:
  file.touch:
    - name: /opt/so/state/influxdbmod.py.patched
    - onchanges:
      - file: influxdbmod.py_shard_duration_patch


