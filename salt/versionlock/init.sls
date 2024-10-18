# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% if grains.os_family == 'Debian' or (grains.os_family == 'RedHat' and salt['pkg.version']('python3-dnf-plugin-versionlock') !=  "") %}
{%   from 'versionlock/map.jinja' import VERSIONLOCKMERGED %}
{%   for pkg in VERSIONLOCKMERGED.hold %}
{{pkg}}_held:
  pkg.held:
    - name: {{pkg}}
{%   endfor %}

{%   for pkg in VERSIONLOCKMERGED.UNHOLD %}
{{pkg}}_unheld:
  pkg.unheld:
    - name: {{pkg}}
{%   endfor %}
{% endif %}
