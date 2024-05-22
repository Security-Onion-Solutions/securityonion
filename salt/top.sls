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
    - firewall
    - sensoroni
    - telegraf
    - nginx
    - healthcheck
    - pcap
    - strelka
    - suricata
    - zeek
    - elasticfleet.install_agent_grid
    - stig

  '*_eval and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - sensor
    - ca
    - ssl
    - firewall
    - registry
    - nginx
    - manager
    - elasticsearch
    - kratos
    - soc
    - sensoroni
    - influxdb
    - telegraf
    - backup.config_backup
    - idstools
    - suricata.manager
    - elastic-fleet-package-registry
    - kibana
    - curator.disabled
    - elastalert
    - utility
    - elasticfleet
    - healthcheck
    - pcap
    - strelka
    - suricata
    - zeek

  '*_manager and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - firewall
    - registry
    - nginx
    - manager
    - elasticsearch
    - kratos
    - strelka.manager
    - soc
    - sensoroni
    - influxdb
    - telegraf
    - backup.config_backup
    - idstools
    - suricata.manager
    - logstash
    - redis
    - elastic-fleet-package-registry
    - kibana
    - curator.disabled
    - elastalert
    - utility
    - elasticfleet
    - stig

  '*_standalone and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - sensor
    - ca
    - ssl
    - firewall
    - registry
    - nginx
    - manager
    - elasticsearch
    - kratos
    - soc
    - sensoroni
    - influxdb
    - telegraf
    - backup.config_backup
    - idstools
    - suricata.manager
    - logstash
    - redis
    - elastic-fleet-package-registry
    - kibana
    - curator.disabled
    - elastalert
    - utility
    - elasticfleet
    - healthcheck
    - pcap
    - strelka
    - suricata
    - zeek
    - stig

  '*_searchnode and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - firewall
    - elasticsearch
    - logstash
    - sensoroni
    - telegraf
    - nginx
    - elasticfleet.install_agent_grid
    - stig

  '*_managersearch and G@saltversion:{{saltversion}}':
    - match: compound
    - salt.master
    - ca
    - ssl
    - firewall
    - registry
    - nginx
    - manager
    - elasticsearch
    - kratos
    - strelka.manager
    - soc
    - sensoroni
    - influxdb
    - telegraf
    - backup.config_backup
    - idstools
    - suricata.manager
    - logstash
    - redis
    - elastic-fleet-package-registry
    - kibana
    - curator.disabled
    - elastalert
    - utility
    - elasticfleet
    - stig

  '*_heavynode and G@saltversion:{{saltversion}}':
    - match: compound
    - sensor
    - ssl
    - firewall
    - sensoroni
    - telegraf
    - nginx
    - elasticsearch
    - logstash
    - redis
    - curator.disabled
    - pcap
    - strelka
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
    - firewall
    - registry
    - nginx
    - manager
    - elasticsearch
    - kratos
    - strelka.manager
    - soc
    - sensoroni
    - influxdb
    - telegraf
    - idstools
    - suricata.manager
    - elastic-fleet-package-registry
    - kibana
    - utility
    - elasticfleet
    - pcap
    - suricata
    - zeek

  '*_receiver and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - firewall
    - sensoroni
    - telegraf
    - logstash
    - redis
    - elasticfleet.install_agent_grid

  '*_idh and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - firewall
    - sensoroni
    - telegraf
    - elasticfleet.install_agent_grid
    - idh

  '*_fleet and G@saltversion:{{saltversion}}':
    - match: compound
    - ssl
    - firewall
    - sensoroni
    - telegraf
    - logstash
    - nginx
    - elasticfleet
    - elasticfleet.install_agent_grid

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
