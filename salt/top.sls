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
    - common
    - docker
    - docker_clean

  '*_sensor and G@saltversion:{{saltversion}}':
    - match: compound
    - sensor
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
    - elasticfleet.install_agent_grid
    - stig

  '*_eval and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - sensor
    - ca
    - ssl
    - registry
    - manager
    - backup.config_backup
    - nginx
    - influxdb
    - soc
    - kratos
    - sensoroni
    - telegraf
    - firewall
    - idstools
    - suricata.manager
    - healthcheck
    - elasticsearch
    - elastic-fleet-package-registry
    - kibana
    - pcap
    - suricata
    - zeek
    - strelka
    - curator.disabled
    - elastalert
    - utility
    - elasticfleet

  '*_manager and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - nginx
    - influxdb
    - strelka.manager
    - soc
    - kratos
    - firewall
    - manager
    - sensoroni
    - telegraf
    - backup.config_backup
    - idstools
    - suricata.manager
    - elasticsearch
    - logstash
    - redis
    - elastic-fleet-package-registry
    - kibana
    - curator.disabled
    - elastalert
    - utility
    - elasticfleet
    - stig
    - kafka

  '*_standalone and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - sensor
    - ca
    - ssl
    - registry
    - manager
    - backup.config_backup
    - nginx
    - influxdb
    - soc
    - kratos
    - firewall
    - sensoroni
    - telegraf
    - idstools
    - suricata.manager
    - healthcheck
    - elasticsearch
    - logstash
    - redis
    - elastic-fleet-package-registry
    - kibana
    - pcap
    - suricata
    - zeek
    - strelka
    - curator.disabled
    - elastalert
    - utility
    - elasticfleet
    - stig
    - kafka

  '*_searchnode and G@saltversion:{{saltversion}}':
    - match: compound
    - firewall
    - ssl
    - elasticsearch
    - logstash
    - sensoroni
    - telegraf
    - nginx
    - elasticfleet.install_agent_grid
    - stig
    - kafka

  '*_managersearch and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - registry
    - nginx
    - influxdb
    - strelka.manager
    - soc
    - kratos
    - firewall
    - manager
    - sensoroni
    - telegraf
    - backup.config_backup
    - idstools
    - suricata.manager
    - elasticsearch
    - logstash
    - redis
    - curator.disabled
    - elastic-fleet-package-registry
    - kibana
    - elastalert
    - utility
    - elasticfleet
    - stig
    - kafka

  '*_heavynode and G@saltversion:{{saltversion}}':
    - match: compound
    - sensor
    - ssl
    - sensoroni
    - telegraf
    - nginx
    - firewall
    - elasticsearch
    - logstash
    - redis
    - curator.disabled
    - strelka
    - pcap
    - suricata
    - zeek
    - elasticfleet.install_agent_grid
    - elasticagent

  '*_import and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - sensor
    - ca
    - ssl
    - registry
    - manager
    - nginx
    - influxdb
    - strelka.manager
    - soc
    - kratos
    - sensoroni
    - telegraf
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

  '*_receiver and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
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
    - ssl
    - sensoroni
    - telegraf
    - firewall
    - elasticfleet.install_agent_grid
    - idh

  '*_fleet and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - sensoroni
    - telegraf
    - firewall
    - logstash
    - nginx
    - elasticfleet
    - elasticfleet.install_agent_grid
    - schedule

  '*_desktop and G@saltversion:{{saltversion}}':
    - ssl
    - sensoroni
    - telegraf
    - elasticfleet.install_agent_grid

  'J@desktop:gui:enabled:^[Tt][Rr][Uu][Ee]$ and ( G@saltversion:{{saltversion}} and G@os:OEL )':
    - match: compound
    - desktop

  'J@desktop:gui:enabled:^[Ff][Aa][Ll][Ss][Ee]$ and ( G@saltversion:{{saltversion}} and G@os:OEL )':
    - match: compound
    - desktop.remove_gui
