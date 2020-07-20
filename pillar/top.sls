base:
  '*':
    - patch.needs_restarting

  '*_eval or *_helix or *_heavynode or *_sensor or *_standalone':
    - match: compound
    - zeek

  '*_managersearch or *_heavynode':
    - match: compound
    - logstash
    - logstash.manager
    - logstash.search
    - elasticsearch.search

  '*_sensor':
    - static
    - zeeklogs
    - healthcheck.sensor
    - minions.{{ grains.id }}

  '*_manager or *_managersearch':
    - match: compound
    - static
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
    - static
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
    - static
    - minions.{{ grains.id }}

  '*_node':
    - static
    - minions.{{ grains.id }}

  '*_heavynode':
    - static
    - zeeklogs
    - minions.{{ grains.id }}

  '*_helix':
    - static
    - fireeye
    - zeeklogs
    - logstash
    - logstash.helix
    - minions.{{ grains.id }}

  '*_fleet':
    - static
    - data.*
    - secrets
    - minions.{{ grains.id }}

  '*_searchnode':
    - static
    - logstash
    - logstash.search
    - elasticsearch.search
    - minions.{{ grains.id }}
