# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

docker_module_package:
  file.recurse:
    - name: /opt/so/conf/salt/module_packages/docker
    - source: salt://salt/module_packages/docker
    - clean: True
    - makedirs: True

# fail hard on this state so that soup would be cancelled on a manager (eventhough salt would have already updated)
# on a non manager, failing hard here will prevent the minion from upgrading
# we want to fail hard here to prevent the minion from upgrading and potetially being able to manager docker containers from a dep mismatch
docker_python_module_install:
  cmd.run:
    - name: /opt/saltstack/salt/bin/python3.10 -m pip install docker --no-index --find-links=/opt/so/conf/salt/module_packages/docker/ --upgrade
    - onchanges:
      - file: docker_module_package
    - failhard: True
