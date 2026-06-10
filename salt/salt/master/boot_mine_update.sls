# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# Manages /etc/systemd/system/so-boot-mine-update.service, a manager-only
# Type=oneshot unit that pushes `salt '*' mine.update` once per boot, ordered
# before so-boot-highstate.service so mine-backed pillars (node IPs, ES/Redis/
# Logstash discovery) are fresh before the boot highstate renders them.

include:
  - systemd.reload

so_boot_mine_update_unit_file:
  file.managed:
    - name: /etc/systemd/system/so-boot-mine-update.service
    - source: salt://salt/service/so-boot-mine-update.service
    - onchanges_in:
      - module: systemd_reload

# Only enable once setup is complete. Until then the gate file is missing and
# the unit's own ConditionPathExists would no-op it anyway.
so_boot_mine_update_service:
  service.enabled:
    - name: so-boot-mine-update.service
    - onlyif: test -e /opt/so/state/setup-complete
    - require:
      - file: so_boot_mine_update_unit_file
      - module: systemd_reload
