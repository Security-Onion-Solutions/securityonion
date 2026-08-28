# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'vars/globals.map.jinja' import GLOBALS %}

# Manages /etc/systemd/system/so-boot-highstate.service, a Type=oneshot
# RemainAfterExit=yes unit that runs `salt-call state.highstate` exactly once
# per system boot. Replaces the legacy `startup_states: highstate` minion
# config, which fired on every salt-minion service restart (causing a redundant
# highstate whenever a highstate itself restarted salt-minion).

include:
  - systemd.reload

so_boot_highstate_unit_file:
  file.managed:
    - name: /etc/systemd/system/so-boot-highstate.service
    - source: salt://salt/service/so-boot-highstate.service
    - onchanges_in:
      - module: systemd_reload

# Non-managers never apply salt.minion during setup, so reaching this state means
# setup is finished and the marker is safe to write unconditionally. This also
# heals nodes installed before this fix, which have no marker and no legacy
# startup_states line to grep for. Managers do highstate mid-setup, so they only
# get the marker from the legacy upgrade signal; fresh installs get it from
# mark_setup_complete in setup/so-functions.
mark_setup_complete:
  file.managed:
    - name: /opt/so/state/setup-complete
    - replace: false
    - makedirs: True
{% if GLOBALS.is_manager %}
    - onlyif: "grep -qx 'startup_states: highstate' /etc/salt/minion"
{% endif %}
    - require_in:
      - service: so_boot_highstate_service

# Only enable once setup is complete. Until then the gate file is missing and
# the unit's own ConditionPathExists would no-op it anyway.
so_boot_highstate_service:
  service.enabled:
    - name: so-boot-highstate.service
    - onlyif: test -e /opt/so/state/setup-complete
    - require:
      - file: so_boot_highstate_unit_file
      - module: systemd_reload
