{% from 'vars/globals.map.jinja' import GLOBALS %}

include:
  {% if GLOBALS.os == 'CentOS Stream' %}
  - repo.client.centos
  {% elif GLOBALS.os == 'ol9' %}
  - repo.client.oracle
  {% else %} 
  - repo.client.{{grains.os | lower}}
  {% endif %}