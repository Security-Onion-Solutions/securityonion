{% from "salt/map.jinja" import SALT_STATE_CODE_PATH with context %}
{% from "salt/map.jinja" import SALT_MODULE_CODE_PATH with context %}

securityonion_python3_influxdb:
  pkg.installed:
    - name: securityonion-python3-influxdb

#https://github.com/saltstack/salt/issues/59766
influxdb_continuous_query.present_patch:
  file.patch:
    - name: {{ SALT_STATE_CODE_PATH }}/influxdb_continuous_query.py
    - source: salt://salt/files/influxdb_continuous_query.py.patch
    - pkg: securityonion_python3_influxdb

#https://github.com/saltstack/salt/issues/59761
influxdb_retention_policy.present_patch:
  file.patch:
    - name: {{ SALT_STATE_CODE_PATH }}/influxdb_retention_policy.py
    - source: salt://salt/files/influxdb_retention_policy.py.patch
    - pkg: securityonion_python3_influxdb

influxdbmod.py_shard_duration_patch:
  file.patch:
    - name: {{ SALT_MODULE_CODE_PATH }}/influxdbmod.py
    - source: salt://salt/files/influxdbmod.py.patch
    - pkg: securityonion_python3_influxdb