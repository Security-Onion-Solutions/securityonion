# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% set ONEDIR_PACKAGES = {'relenv': '0.22.27', 'pip': '26.2.2', 'certifi': '2026.10.19'} %}

{% if grains.saltversion == '3006.19' %}
onedir_package:
  file.recurse:
    - name: /opt/so/conf/salt/module_packages/onedir
    - source: salt://salt/module_packages/onedir
    - clean: True
    - makedirs: True

# Backport of salt 3006.29 (PR 70466): certifi 2026.10.19 and pip 26.2.2 drop the compromised
# eMudhra/emSign root. relenv must move with pip: 0.22.2's runtime wrapper hardcodes pre-26.2 pip
# install() signatures, so a lone pip upgrade breaks every later pip run in the onedir. Installing
# all three in one invocation under the stock pip avoids ever being in that state.
onedir_python_module_install:
  cmd.run:
    - name: /opt/saltstack/salt/bin/python3.10 -m pip install --no-index --find-links=/opt/so/conf/salt/module_packages/onedir/ --upgrade --root-user-action=ignore {% for pkg, ver in ONEDIR_PACKAGES.items() %}{{ pkg }}=={{ ver }} {% endfor %}
    - unless: /opt/saltstack/salt/bin/python3.10 -c 'import {{ ONEDIR_PACKAGES.keys() | join(", ") }}; assert {% for pkg, ver in ONEDIR_PACKAGES.items() %}{{ pkg }}.__version__ == "{{ ver }}"{% if not loop.last %} and {% endif %}{% endfor %}'
    - require:
      - file: onedir_package
    - require_in:
      - cmd: docker_python_module_install
    - failhard: True
{% endif %}

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
