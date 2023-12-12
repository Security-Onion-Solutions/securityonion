base:
  '*':
    - global.soc_global
    - global.adv_global
    - docker.soc_docker
    - docker.adv_docker
    - influxdb.token
    - logrotate.soc_logrotate
    - logrotate.adv_logrotate
    - ntp.soc_ntp
    - ntp.adv_ntp
    - patch.needs_restarting
    - patch.soc_patch
    - patch.adv_patch
    - sensoroni.soc_sensoroni
    - sensoroni.adv_sensoroni
    - telegraf.soc_telegraf
    - telegraf.adv_telegraf

  '* and not *_desktop':
    - firewall.soc_firewall
    - firewall.adv_firewall
    - nginx.soc_nginx
    - nginx.adv_nginx
    - node_data.ips

  '*_manager or *_managersearch':
    - match: compound
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
    {% endif %}
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/kibana/secrets.sls') %}
    - kibana.secrets
    {% endif %}
    - secrets
    - manager.soc_manager
    - manager.adv_manager
    - idstools.soc_idstools
    - idstools.adv_idstools
    - logstash.nodes
    - logstash.soc_logstash
    - logstash.adv_logstash
    - soc.soc_soc
    - soc.adv_soc
    - soc.license
    - soctopus.soc_soctopus
    - soctopus.adv_soctopus
    - kibana.soc_kibana
    - kibana.adv_kibana
    - kratos.soc_kratos
    - kratos.adv_kratos
    - redis.soc_redis
    - redis.adv_redis
    - influxdb.soc_influxdb
    - influxdb.adv_influxdb
    - elasticsearch.soc_elasticsearch
    - elasticsearch.adv_elasticsearch
    - elasticfleet.soc_elasticfleet
    - elasticfleet.adv_elasticfleet
    - elastalert.soc_elastalert
    - elastalert.adv_elastalert
    - backup.soc_backup
    - backup.adv_backup
    - soctopus.soc_soctopus
    - soctopus.adv_soctopus
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_sensor':
    - healthcheck.sensor
    - strelka.soc_strelka
    - strelka.adv_strelka
    - zeek.soc_zeek
    - zeek.adv_zeek
    - bpf.soc_bpf
    - bpf.adv_bpf
    - pcap.soc_pcap
    - pcap.adv_pcap
    - suricata.soc_suricata
    - suricata.adv_suricata
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
    - kratos.soc_kratos
    - elasticsearch.soc_elasticsearch
    - elasticsearch.adv_elasticsearch
    - elasticfleet.soc_elasticfleet
    - elasticfleet.adv_elasticfleet
    - elastalert.soc_elastalert
    - elastalert.adv_elastalert
    - manager.soc_manager
    - manager.adv_manager
    - idstools.soc_idstools
    - idstools.adv_idstools
    - soc.soc_soc
    - soc.adv_soc
    - soc.license
    - soctopus.soc_soctopus
    - soctopus.adv_soctopus
    - kibana.soc_kibana
    - kibana.adv_kibana
    - strelka.soc_strelka
    - strelka.adv_strelka
    - kratos.soc_kratos
    - kratos.adv_kratos
    - redis.soc_redis
    - redis.adv_redis
    - influxdb.soc_influxdb
    - influxdb.adv_influxdb
    - backup.soc_backup
    - backup.adv_backup
    - zeek.soc_zeek
    - zeek.adv_zeek
    - bpf.soc_bpf
    - bpf.adv_bpf
    - pcap.soc_pcap
    - pcap.adv_pcap
    - suricata.soc_suricata
    - suricata.adv_suricata
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_standalone':
    - logstash.nodes
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
    - elasticfleet.soc_elasticfleet
    - elasticfleet.adv_elasticfleet
    - elastalert.soc_elastalert
    - elastalert.adv_elastalert
    - manager.soc_manager
    - manager.adv_manager
    - soc.soc_soc
    - soc.adv_soc
    - soc.license
    - soctopus.soc_soctopus
    - soctopus.adv_soctopus
    - kibana.soc_kibana
    - kibana.adv_kibana
    - strelka.soc_strelka
    - strelka.adv_strelka
    - backup.soc_backup
    - backup.adv_backup
    - zeek.soc_zeek
    - zeek.adv_zeek
    - bpf.soc_bpf
    - bpf.adv_bpf
    - pcap.soc_pcap
    - pcap.adv_pcap
    - suricata.soc_suricata
    - suricata.adv_suricata
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_heavynode':
    - elasticsearch.auth
    - logstash.nodes
    - logstash.soc_logstash
    - logstash.adv_logstash
    - elasticsearch.soc_elasticsearch
    - elasticsearch.adv_elasticsearch
    - redis.soc_redis
    - redis.adv_redis
    - zeek.soc_zeek
    - zeek.adv_zeek
    - bpf.soc_bpf
    - bpf.adv_bpf
    - pcap.soc_pcap
    - pcap.adv_pcap
    - suricata.soc_suricata
    - suricata.adv_suricata
    - strelka.soc_strelka
    - strelka.adv_strelka
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_idh':
    - idh.soc_idh
    - idh.adv_idh
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_searchnode':
    - logstash.nodes
    - logstash.soc_logstash
    - logstash.adv_logstash
    - elasticsearch.soc_elasticsearch
    - elasticsearch.adv_elasticsearch
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
    {% endif %}
    - redis.soc_redis
    - redis.adv_redis
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_receiver':
    - logstash.nodes
    - logstash.soc_logstash
    - logstash.adv_logstash
    {% if salt['file.file_exists']('/opt/so/saltstack/local/pillar/elasticsearch/auth.sls') %}
    - elasticsearch.auth
    {% endif %}
    - redis.soc_redis
    - redis.adv_redis
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
    - elasticfleet.soc_elasticfleet
    - elasticfleet.adv_elasticfleet
    - elastalert.soc_elastalert
    - elastalert.adv_elastalert
    - manager.soc_manager
    - manager.adv_manager
    - soc.soc_soc
    - soc.adv_soc
    - soc.license
    - soctopus.soc_soctopus
    - soctopus.adv_soctopus
    - kibana.soc_kibana
    - kibana.adv_kibana
    - backup.soc_backup
    - backup.adv_backup
    - kratos.soc_kratos
    - kratos.adv_kratos
    - redis.soc_redis
    - redis.adv_redis
    - influxdb.soc_influxdb
    - influxdb.adv_influxdb
    - zeek.soc_zeek
    - zeek.adv_zeek
    - bpf.soc_bpf
    - bpf.adv_bpf
    - pcap.soc_pcap
    - pcap.adv_pcap
    - suricata.soc_suricata
    - suricata.adv_suricata
    - strelka.soc_strelka
    - strelka.adv_strelka
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_fleet':
    - backup.soc_backup
    - backup.adv_backup
    - logstash.nodes
    - logstash.soc_logstash
    - logstash.adv_logstash
    - elasticfleet.soc_elasticfleet
    - elasticfleet.adv_elasticfleet
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}

  '*_desktop':
    - minions.{{ grains.id }}
    - minions.adv_{{ grains.id }}
