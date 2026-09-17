# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

# These wheels are pip-installed by root below, so they cannot live under /opt/so/conf:
# that directory is 939:939 mode 770, and write permission on it is what lets uid 939
# rename the tree aside and substitute its own wheels between this state and the install.
# Hardening only the files here would not help -- renaming an entry needs write on the
# parent, not on the entry.
docker_module_package:
  file.recurse:
    - name: /opt/saltstack/module_packages/docker
    - source: salt://salt/module_packages/docker
    - user: root
    - group: root
    - dir_mode: 755
    - file_mode: 644
    - clean: True
    - makedirs: True

# Installs before this change left wheels in a socore-writable directory; nothing reads
# them now, but leaving them behind leaves a writable staging area lying around.
old_docker_module_package:
  file.absent:
    - name: /opt/so/conf/salt/module_packages

# fail hard on this state so that soup would be cancelled on a manager (eventhough salt would have already updated)
# on a non manager, failing hard here will prevent the minion from upgrading
# we want to fail hard here to prevent the minion from upgrading and potetially being able to manager docker containers from a dep mismatch
docker_python_module_install:
  cmd.run:
    - name: /opt/saltstack/salt/bin/python3.10 -m pip install docker --no-index --find-links=/opt/saltstack/module_packages/docker/ --upgrade
    - onchanges:
      - file: docker_module_package
    - failhard: True
