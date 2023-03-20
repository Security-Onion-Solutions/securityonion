base:
  '*':
    - patch.needs_restarting
    - ntp.soc_ntp
    - ntp.adv_ntp
    - logrotate
    - docker.soc_docker
    - docker.adv_docker
    - sensoroni.soc_sensoroni
    - sensoroni.adv_sensoroni
    - telegraf.soc_telegraf
    - telegraf.adv_telegraf
    - influxdb.token
    - node_data.ips

  '* and not *_eval and not *_import':
    - logstash.nodes

  '*_eval or *_heavynode or *_sensor or *_standalone or *_import':
    - match: compound
    - zeek
    - bpf.soc_bpf
    - bpf.adv_bpf

  '*_managersearch or *_heavynode':
    - match: compound
    - logstash
    - logstash.manager
    - logstash.search
    - logstash.soc_logstash
    - logstash.adv_logstash
    - elasticsearch.index_templates
    - elasticsearch.soc_elasticsearch
    - elasticsearch.adv_elasticsearch

  '*_manager':
    - logstash
    - logstash.manager
    - logstash.soc_logstash
    - logstash.adv_logstash
    - elasticsearch.index_templates

  '*_manager or *_managersearch':
    - match: compound
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
    {% endif %}
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/kibana/secrets.sls') %}
    - kibana.secrets
    {% endif %}
    - secrets
    - soc_global
    - adv_global
    - manager.soc_manager
    - manager.adv_manager
    - idstools.soc_idstools
    - idstools.adv_idstools
    - soc.soc_soc
    - soc.adv_soc
    - kratos.soc_kratos
    - kratos.adv_kratos
    - redis.soc_redis
    - redis.adv_redis
    - influxdb.soc_influxdb
    - influxdb.adv_influxdb
    - elasticsearch.soc_elasticsearch
    - elasticsearch.adv_elasticsearch
    - backup.soc_backup
    - backup.adv_backup
    - firewall.soc_firewall
    - firewall.adv_firewall
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_sensor':
    - healthcheck.sensor
    - soc_global
    - adv_global
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_eval':
    - secrets
    - healthcheck.eval
    - elasticsearch.index_templates
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
    {% endif %}
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/kibana/secrets.sls') %}
    - kibana.secrets
    {% endif %}
    - soc_global
    - kratos.soc_kratos
    - elasticsearch.soc_elasticsearch
    - elasticsearch.adv_elasticsearch
    - manager.soc_manager
    - manager.adv_manager
    - idstools.soc_idstools
    - idstools.adv_idstools
    - soc.soc_soc
    - kratos.soc_kratos
    - kratos.adv_kratos
    - redis.soc_redis
    - redis.adv_redis
    - influxdb.soc_influxdb
    - influxdb.adv_influxdb
    - backup.soc_backup
    - backup.adv_backup
    - firewall.soc_firewall
    - firewall.adv_firewall
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_standalone':
    - logstash
    - logstash.manager
    - logstash.search
    - logstash.soc_logstash
    - logstash.adv_logstash
    - elasticsearch.index_templates
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
    {% endif %}
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/kibana/secrets.sls') %}
    - kibana.secrets
    {% endif %}
    - secrets
    - healthcheck.standalone
    - soc_global
    - idstools.soc_idstools
    - idstools.adv_idstools
    - kratos.soc_kratos
    - kratos.adv_kratos
    - redis.soc_redis
    - redis.adv_redis
    - influxdb.soc_influxdb
    - influxdb.adv_influxdb
    - elasticsearch.soc_elasticsearch
    - elasticsearch.adv_elasticsearch
    - manager.soc_manager
    - manager.adv_manager
    - soc.soc_soc
    - backup.soc_backup
    - backup.adv_backup
    - firewall.soc_firewall
    - firewall.adv_firewall
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_heavynode':
    - elasticsearch.auth
    - soc_global
    - redis.soc_redis
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_idh':
    - soc_global
    - adv_global
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_searchnode':
    - logstash
    - logstash.search
    - logstash.soc_logstash
    - logstash.adv_logstash
    - elasticsearch.index_templates
    - elasticsearch.soc_elasticsearch
    - elasticsearch.adv_elasticsearch
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
    {% endif %}
    - redis.soc_redis
    - soc_global
    - adv_global
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_receiver':
    - logstash
    - logstash.receiver
    - logstash.soc_logstash
    - logstash.adv_logstash
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
    {% endif %}
    - redis.soc_redis
    - redis.adv_redis
    - soc_global
    - adv_global
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_import':
    - secrets
    - elasticsearch.index_templates
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
    {% endif %}
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/kibana/secrets.sls') %}
    - kibana.secrets
    {% endif %}
    - kratos.soc_kratos
    - elasticsearch.soc_elasticsearch
    - elasticsearch.adv_elasticsearch
    - manager.soc_manager
    - manager.adv_manager
    - soc.soc_soc
    - soc_global
    - adv_global
    - backup.soc_backup
    - backup.adv_backup
    - kratos.soc_kratos
    - kratos.adv_kratos
    - redis.soc_redis
    - redis.adv_redis
    - influxdb.soc_influxdb
    - influxdb.adv_influxdb
    - firewall.soc_firewall
    - firewall.adv_firewall
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_workstation':
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}
