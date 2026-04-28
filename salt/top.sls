# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% import_yaml 'salt/minion.defaults.yaml' as saltversion %}
{% set saltversion = saltversion.salt.minion.version %}
{% set INSTALLEDSALTVERSION = grains.saltversion %}

base:
  'salt-cloud:driver:libvirt':
    - match: grain
    - storage
    - vm.status
    - vm.user

  '*':
    - cron.running
    - repo.client
    - versionlock
    - ntp
    - schedule
    - logrotate

  # manager node on proper salt version with empty node_data pillar
  '( *_manager* or *_eval or *_import or *_standalone ) and G@saltversion:{{saltversion}} and I@node_data:False':
    - match: compound
    - salt.minion
    - salt.master.mine_update_highstate

  'not G@saltversion:{{saltversion}}':
    - match: compound
    - salt.minion-state-apply-test
    - salt.minion

  # all non managers on the proper salt version
  'not ( *_manager* or *_eval or *_import or *_standalone ) and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.minion
    - ca
    - patch.os.schedule
    - motd
    - salt.minion-check
    - salt.lasthighstate
    - common
    - docker
    - docker_clean

  # all managers on proper salt version node_data pillar not empty
  '( *_manager* or *_eval or *_import or *_standalone ) and G@saltversion:{{saltversion}} and not I@node_data:False':
    - match: compound
    - salt.minion
    - ca
    - patch.os.schedule
    - motd
    - salt.minion-check
    - salt.lasthighstate
    - common
    - docker
    - docker_clean

  '*_eval and G@saltversion:{{saltversion}} and not I@node_data:False':
    - match: compound
    - salt.master
    - sensor
    - registry
    - manager
    - backup.config_backup
    - nginx
    - influxdb
    - postgres
    - soc
    - kratos
    - hydra
    - sensoroni
    - telegraf
    - firewall
    - healthcheck
    - elasticsearch
    - elastic-fleet-package-registry
    - kibana
    - suricata
    - zeek
    - strelka
    - elastalert
    - utility
    - elasticfleet
    - pcap.cleanup

  '*_standalone and G@saltversion:{{saltversion}} and not I@node_data:False':
    - match: compound
    - salt.master
    - sensor
    - registry
    - manager
    - backup.config_backup
    - nginx
    - influxdb
    - postgres
    - soc
    - kratos
    - hydra
    - firewall
    - sensoroni
    - telegraf
    - healthcheck
    - elasticsearch
    - logstash
    - redis
    - elastic-fleet-package-registry
    - kibana
    - suricata
    - zeek
    - strelka
    - elastalert
    - utility
    - elasticfleet
    - stig
    - kafka
    - pcap.cleanup

  '*_manager or *_managerhype and G@saltversion:{{saltversion}} and not I@node_data:False':
    - match: compound
    - salt.master
    - registry
    - nginx
    - influxdb
    - postgres
    - strelka.manager
    - soc
    - kratos
    - hydra
    - firewall
    - manager
    - sensoroni
    - telegraf
    - backup.config_backup
    - elasticsearch
    - logstash
    - redis
    - elastic-fleet-package-registry
    - kibana
    - elastalert
    - utility
    - elasticfleet
    - stig
    - kafka

  '*_managerhype and I@features:vrt and G@saltversion:{{saltversion}}':
    - match: compound
    - manager.hypervisor

  '*_managersearch and G@saltversion:{{saltversion}} and not I@node_data:False':
    - match: compound
    - salt.master
    - registry
    - nginx
    - influxdb
    - postgres
    - strelka.manager
    - soc
    - kratos
    - hydra
    - firewall
    - manager
    - sensoroni
    - telegraf
    - backup.config_backup
    - elasticsearch
    - logstash
    - redis
    - elastic-fleet-package-registry
    - kibana
    - elastalert
    - utility
    - elasticfleet
    - stig
    - kafka

  '*_import and G@saltversion:{{saltversion}} and not I@node_data:False':
    - match: compound
    - salt.master
    - sensor
    - registry
    - manager
    - nginx
    - influxdb
    - postgres
    - strelka.manager
    - soc
    - kratos
    - hydra
    - sensoroni
    - telegraf
    - firewall
    - elasticsearch
    - elastic-fleet-package-registry
    - kibana
    - utility
    - suricata
    - zeek
    - elasticfleet
    - pcap.cleanup

  '*_searchnode and G@saltversion:{{saltversion}}':
    - match: compound
    - firewall
    - elasticsearch
    - logstash
    - sensoroni
    - telegraf
    - nginx
    - elasticfleet.install_agent_grid
    - stig
    - kafka

  '*_sensor and G@saltversion:{{saltversion}}':
    - match: compound
    - sensor
    - sensoroni
    - telegraf
    - firewall
    - nginx
    - suricata
    - healthcheck
    - zeek
    - strelka
    - elasticfleet.install_agent_grid
    - stig
    - pcap.cleanup

  '*_heavynode and G@saltversion:{{saltversion}}':
    - match: compound
    - sensor
    - sensoroni
    - telegraf
    - nginx
    - firewall
    - elasticsearch
    - logstash
    - redis
    - strelka
    - suricata
    - zeek
    - elasticfleet.install_agent_grid
    - elasticagent
    - pcap.cleanup

  '*_receiver and G@saltversion:{{saltversion}}':
    - match: compound
    - sensoroni
    - telegraf
    - firewall
    - logstash
    - redis
    - elasticfleet.install_agent_grid
    - kafka
    - stig

  '*_idh and G@saltversion:{{saltversion}}':
    - match: compound
    - sensoroni
    - telegraf
    - firewall
    - elasticfleet.install_agent_grid
    - idh

  '*_fleet and G@saltversion:{{saltversion}}':
    - match: compound
    - sensoroni
    - telegraf
    - firewall
    - logstash
    - nginx
    - elasticfleet
    - elasticfleet.install_agent_grid
    - schedule
    - stig

  '*_hypervisor and I@features:vrt and G@saltversion:{{saltversion}}':
    - match: compound
    - sensoroni
    - telegraf
    - firewall
    - hypervisor
    - libvirt
    - libvirt.images
    - elasticfleet.install_agent_grid
    - stig
  
  '*_desktop and G@saltversion:{{saltversion}}':
    - sensoroni
    - telegraf
    - elasticfleet.install_agent_grid
    - stig

  'J@desktop:gui:enabled:^[Tt][Rr][Uu][Ee]$ and ( G@saltversion:{{saltversion}} and G@os:OEL )':
    - match: compound
    - desktop

  'J@desktop:gui:enabled:^[Ff][Aa][Ll][Ss][Ee]$ and ( G@saltversion:{{saltversion}} and G@os:OEL )':
    - match: compound
    - desktop.remove_gui
