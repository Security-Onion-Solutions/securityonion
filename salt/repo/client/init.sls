include:
  {% if GLOBALS.os == 'CentOS Stream' %}
  - repo.client.centos
  {% else %} 
  - repo.client.{{grains.os | lower}}
  {% endif %}