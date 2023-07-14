{% from 'vars/globals.map.jinja' import GLOBALS %}
{% if GLOBALS.os == 'OEL' %}
include:
  - repo.client.oracle
{% endif %}