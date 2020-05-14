base:
  '*':
    - patch.needs_restarting

  '*_eval or *_helix or *_heavynode or *_sensor':
    - match: compound
    - zeek

  '*_mastersearch or *_heavynode':
    - match: compound
    - logstash
    - logstash.master
    - logstash.search

  '*_sensor':
    - static
    - firewall.*
    - brologs
    - healthcheck.sensor
    - minions.{{ grains.id }}

  '*_master or *_mastersearch':
    - match: compound
    - static
    - firewall.*
    - data.*
    - secrets
    - minions.{{ grains.id }}

  '*_master':
    - logstash
    - logstash.master

  '*_eval':
    - static
    - firewall.*
    - data.*
    - brologs
    - secrets
    - healthcheck.eval
    - minions.{{ grains.id }}

    '*_standalone':
    - logstash
    - logstash.master
    - logstash.search
    - firewall.*
    - data.*
    - brologs
    - secrets
    - healthcheck.standalone
    - static
    - minions.{{ grains.id }}

  '*_node':
    - static
    - firewall.*
    - minions.{{ grains.id }}

  '*_heavynode':
    - static
    - firewall.*
    - brologs
    - minions.{{ grains.id }}

  '*_helix':
    - static
    - firewall.*
    - fireeye
    - brologs
    - logstash
    - logstash.helix
    - minions.{{ grains.id }}

  '*_fleet':
    - static
    - firewall.*
    - data.*
    - secrets
    - minions.{{ grains.id }}

  '*_searchnode':
    - static
    - firewall.*
    - logstash
    - logstash.search
    - minions.{{ grains.id }}
