# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

pyinotify_module_package:
  file.recurse:
    - name: /opt/so/conf/salt/module_packages/pyinotify
    - source: salt://salt/module_packages/pyinotify
    - clean: True
    - makedirs: True

pyinotify_python_module_install:
  cmd.run:
    - name: /opt/saltstack/salt/bin/python3.10 -m pip install pyinotify --no-index --find-links=/opt/so/conf/salt/module_packages/pyinotify/ --upgrade
    - onchanges:
      - file: pyinotify_module_package
    - failhard: True
    - watch_in:
      - service: salt_minion_service
