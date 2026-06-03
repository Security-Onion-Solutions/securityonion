{% from 'vars/globals.map.jinja' import GLOBALS %}
{# OL10 test path uses public repos; skip the SO repo state (which removes public repos and points at /nsm/repo) #}
{% if GLOBALS.os == 'OEL' and GLOBALS.os_version|int == 9 %}
include:
  - repo.client.oracle
{% endif %}