base:
  '*':
    - patch.needs_restarting
    - logrotate

  '* and not *_eval and not *_import':
    - logstash.nodes

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
{% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
{% endif %}
{% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/kibana/secrets.sls') %}
    - kibana.secrets
{% endif %}
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
{% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
{% endif %}
{% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/kibana/secrets.sls') %}
    - kibana.secrets
{% endif %}
    - global
    - minions.{{ grains.id }}

  '*_standalone':
    - logstash
    - logstash.manager
    - logstash.search
    - elasticsearch.search
{% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
{% endif %}
{% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/kibana/secrets.sls') %}
    - kibana.secrets
{% endif %}
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
    - elasticsearch.auth
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

  '*_idh':
    - data.*
    - global
    - minions.{{ grains.id }}

  '*_searchnode':
    - logstash
    - logstash.search
    - elasticsearch.search
    - elasticsearch.auth
    - global
    - minions.{{ grains.id }}
    - data.nodestab

  '*_receiver':
    - logstash
    - logstash.receiver
    - elasticsearch.auth
    - global
    - minions.{{ grains.id }}

  '*_import':
    - zeeklogs
    - secrets
    - elasticsearch.eval
{% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
{% endif %}
{% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/kibana/secrets.sls') %}
    - kibana.secrets
{% endif %}
    - global
    - minions.{{ grains.id }}
