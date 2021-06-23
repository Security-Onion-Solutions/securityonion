base:
  '*':
    - patch.needs_restarting
    - logrotate
    - users

  '*_eval or *_helixsensor or *_heavynode or *_sensor or *_standalone or *_import':
    - match: compound
    - zeek

  '*_managersearch or *_heavynode':
    - match: compound
    - logstash
    - logstash.manager
    - logstash.search
    - elasticsearch.search

  '*_manager':
    - logstash
    - logstash.manager
    - elasticsearch.manager

  '*_manager or *_managersearch':
    - match: compound
    - data.*
    - secrets
    - global
    - minions.{{ grains.id }}

  '*_sensor':
    - zeeklogs
    - healthcheck.sensor
    - global
    - minions.{{ grains.id }}

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
    - zeeklogs
    - global
    - minions.{{ grains.id }}

  '*_helixsensor':
    - fireeye
    - zeeklogs
    - logstash
    - logstash.helix
    - global
    - minions.{{ grains.id }}

  '*_fleet':
    - data.*
    - secrets
    - global
    - minions.{{ grains.id }}

  '*_searchnode':
    - logstash
    - logstash.search
    - elasticsearch.search
    - global
    - minions.{{ grains.id }}
    - data.nodestab

  '*_import':
    - zeeklogs
    - secrets
    - elasticsearch.eval
    - global
    - minions.{{ grains.id }}
