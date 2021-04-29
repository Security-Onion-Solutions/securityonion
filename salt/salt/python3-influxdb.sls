{% from "salt/map.jinja" import SALT_STATE_CODE_PATH with context %}
{% from "salt/map.jinja" import SALT_MODULE_CODE_PATH with context %}
{% from "salt/map.jinja" import PYTHON3INFLUX with context %}
{% from "salt/map.jinja" import PYTHON3INFLUXDEPS with context %}
{% from "salt/map.jinja" import PYTHONINSTALLER with context %}

include:
  - salt.helper-packages

{#
python3_influxdb_dependencies:
  {{PYTHONINSTALLER}}.installed:
    - pkgs: {{ PYTHON3INFLUXDEPS }}
#}

python3_influxdb:
  {{PYTHONINSTALLER}}.installed:
    - name: {{ PYTHON3INFLUX }}

#https://github.com/saltstack/salt/issues/59766
influxdb_continuous_query.present_patch:
  file.patch:
    - name: {{ SALT_STATE_CODE_PATH }}/influxdb_continuous_query.py
    - source: salt://salt/files/influxdb_continuous_query.py.patch
    - require:
      - pkg: python3_influxdb
      - pkg: patch_package

#https://github.com/saltstack/salt/issues/59761
influxdb_retention_policy.present_patch:
  file.patch:
    - name: {{ SALT_STATE_CODE_PATH }}/influxdb_retention_policy.py
    - source: salt://salt/files/influxdb_retention_policy.py.patch
    - require:
      - pkg: python3_influxdb
      - pkg: patch_package

influxdbmod.py_shard_duration_patch:
  file.patch:
    - name: {{ SALT_MODULE_CODE_PATH }}/influxdbmod.py
    - source: salt://salt/files/influxdbmod.py.patch
    - require:
      - pkg: python3_influxdb
      - pkg: patch_package
    - reload_modules: True