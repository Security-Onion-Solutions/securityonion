python3_influxdb:
  pkg.installed:
    - name: python3-influxdb

#https://github.com/saltstack/salt/issues/59766
influxdb_continuous_query.present_patch:
  file.patch:
    - name: /usr/lib/python3.6/site-packages/salt/states/influxdb_continuous_query.py
    - source: salt://salt/files/influxdb_continuous_query.py.patch
    - pkg: python3_influxdb

#https://github.com/saltstack/salt/issues/59761
influxdb_retention_policy.present_patch:
  file.patch:
    - name: /usr/lib/python3.6/site-packages/salt/states/influxdb_retention_policy.py
    - source: salt://salt/files/influxdb_retention_policy.py.patch
    - pkg: python3_influxdb

influxdbmod.py_shard_duration_patch:
  file.patch:
    - name: /usr/lib/python3.6/site-packages/salt/modules/influxdbmod.py
    - source: salt://salt/files/influxdbmod.py.patch
    - pkg: python3_influxdb