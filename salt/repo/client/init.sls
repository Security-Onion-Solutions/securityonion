{% from 'vars/globals.map.jinja' import GLOBALS %}

include:
  {% if GLOBALS.os == 'CentOS Stream' %}
  - repo.client.centos
  {% else %} 
  - repo.client.{{grains.os | lower}}
  {% endif %}