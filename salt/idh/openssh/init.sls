{# This state is designed to only manage the openssh server settings of an IDH node and is seperate from the ssh setting for OpenCanary #}
{% from "idh/openssh/map.jinja" import openssh_map with context %}

openssh:
  pkg.installed:
    - name: {{ openssh_map.server }}
  {% if openssh_map.enable is sameas true %}
  service.running:
    - enable: {{ openssh_map.enable }}
    - name: {{ openssh_map.service }}
    - require:
      - pkg: {{ openssh_map.server }}
  {% else %}
  service.dead:
    - enable: False
    - name: {{ openssh_map.service }}
  {% endif %}
