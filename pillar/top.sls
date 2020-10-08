base:
  '*':
    - patch.needs_restarting
    - logrotate

  '*_eval or *_helix or *_heavynode or *_sensor or *_standalone or *_import':
    - match: compound
    - zeek

  '*_managersearch or *_heavynode':
    - match: compound
    - logstash
    - logstash.manager
    - logstash.search
    - elasticsearch.search

  '*_sensor':
    - global
    - zeeklogs
    - healthcheck.sensor
    - minions.{{ grains.id }}

  '*_manager or *_managersearch':
    - match: compound
    - global
    - data.*
    - secrets
    - minions.{{ grains.id }}

  '*_manager':
    - logstash
    - logstash.manager

  '*_eval':
    - data.*
    - zeeklogs
    - secrets
    - healthcheck.eval
    - elasticsearch.eval
    - global
    - minions.{{ grains.id }}

  '*_standalone':
    - logstash
    - logstash.manager
    - logstash.search
    - elasticsearch.search
    - data.*
    - zeeklogs
    - secrets
    - healthcheck.standalone
    - global
    - minions.{{ grains.id }}

  '*_node':
    - global
    - minions.{{ grains.id }}

  '*_heavynode':
    - global
    - zeeklogs
    - minions.{{ grains.id }}

  '*_helix':
    - global
    - fireeye
    - zeeklogs
    - logstash
    - logstash.helix
    - minions.{{ grains.id }}

  '*_fleet':
    - global
    - data.*
    - secrets
    - minions.{{ grains.id }}

  '*_searchnode':
    - global
    - logstash
    - logstash.search
    - elasticsearch.search
    - minions.{{ grains.id }}

  '*_import':
    - zeeklogs
    - secrets
    - elasticsearch.eval
    - global
    - minions.{{ grains.id }}