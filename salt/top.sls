# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% import_yaml 'salt/minion.defaults.yaml' as saltversion %}
{% set saltversion = saltversion.salt.minion.version %}
{% set INSTALLEDSALTVERSION = grains.saltversion %}

base:

  '*':
    - cron.running
    - repo.client
    - ntp
    - schedule
    - logrotate

  'not G@saltversion:{{saltversion}}':
    - match: compound
    - salt.minion-state-apply-test
    - salt.minion

  '* and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.minion
    - patch.os.schedule
    - motd
    - salt.minion-check
    - salt.lasthighstate
    - docker

  'not *_desktop and G@saltversion:{{saltversion}}':
    - match: compound
    - common
  
  '*_sensor and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - telegraf
    - firewall
    - nginx
    - pcap
    - suricata
    - healthcheck
    - zeek
    - strelka
    - docker_clean
    - elasticfleet.install_agent_grid

  '*_eval and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - manager
    - backup.config_backup
    - nginx
    - telegraf
    - influxdb
    - soc
    - kratos
    - firewall
    - idstools
    - suricata.manager
    - healthcheck
    - mysql
    - elasticsearch
    - elastic-fleet-package-registry
    - kibana
    - pcap
    - suricata
    - zeek
    - strelka
    - curator
    - elastalert
    - utility
    - soctopus
    - playbook
    - redis
    - elasticfleet
    - docker_clean

  '*_manager and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - nginx
    - telegraf
    - influxdb
    - soc
    - kratos
    - firewall
    - manager
    - backup.config_backup
    - idstools
    - suricata.manager
    - mysql
    - elasticsearch
    - logstash
    - redis
    - elastic-fleet-package-registry
    - kibana
    - curator
    - elastalert
    - utility
    - soctopus
    - playbook
    - elasticfleet
    - docker_clean

  '*_standalone and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - manager
    - backup.config_backup
    - nginx
    - telegraf
    - influxdb
    - soc
    - kratos
    - firewall
    - idstools
    - suricata.manager    
    - healthcheck
    - mysql
    - elasticsearch
    - logstash
    - redis
    - elastic-fleet-package-registry
    - kibana
    - pcap
    - suricata
    - zeek
    - strelka
    - curator
    - elastalert
    - utility
    - soctopus
    - playbook
    - elasticfleet
    - docker_clean

  '*_searchnode and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - nginx
    - telegraf
    - firewall
    - elasticsearch
    - logstash
    - elasticfleet.install_agent_grid
    - docker_clean

  '*_managersearch and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - nginx
    - telegraf
    - influxdb
    - soc
    - kratos
    - firewall
    - manager
    - backup.config_backup
    - idstools
    - suricata.manager
    - mysql
    - elasticsearch
    - logstash
    - redis
    - curator
    - elastic-fleet-package-registry
    - kibana
    - elastalert
    - utility
    - soctopus
    - playbook
    - elasticfleet
    - docker_clean

  '*_heavynode and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - nginx
    - telegraf
    - firewall
    - elasticsearch
    - logstash
    - redis
    - curator
    - strelka
    - pcap
    - suricata
    - zeek
    - elasticfleet.install_agent_grid
    - elasticagent
    - docker_clean
  
  '*_import and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - sensoroni
    - manager
    - nginx
    - telegraf
    - influxdb
    - soc
    - kratos
    - firewall
    - idstools
    - suricata.manager
    - pcap
    - elasticsearch
    - elastic-fleet-package-registry
    - kibana
    - utility
    - suricata
    - zeek
    - elasticfleet
    - docker_clean

  '*_receiver and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - telegraf
    - firewall
    - logstash
    - redis
    - elasticfleet.install_agent_grid
    - docker_clean

  '*_idh and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - telegraf
    - firewall
    - elasticfleet.install_agent_grid
    - docker_clean
    - idh

  '*_fleet and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - telegraf
    - firewall
    - logstash
    - elasticfleet
    - elasticfleet.install_agent_grid
    - schedule
    - docker_clean

  'J@desktop:gui:enabled:^[Tt][Rr][Uu][Ee]$ and ( G@saltversion:{{saltversion}} and G@os:Rocky )':
    - match: compound
    - desktop

  'J@desktop:gui:enabled:^[Ff][Aa][Ll][Ss][Ee]$ and ( G@saltversion:{{saltversion}} and G@os:Rocky )':
    - match: compound
    - desktop.remove_gui
