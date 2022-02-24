{% from "idh/openssh/map.jinja" import openssh_map with context %}

include:
  - idh.openssh

{% if grains.os_family == 'RedHat' %}
sshd_selinux:
  selinux.port_policy_present:
    - name: tcp/{{ openssh_map.config.port }}
    - port: {{ openssh_map.config.port }}
    - protocol: tcp
    - sel_type: ssh_port_t
    - prereq:
      - file: openssh_config
{% endif %}

openssh_config:
  file.replace:
    - name: {{ openssh_map.conf }}
    - pattern: '(^|^#)Port \d+$'
    - repl: 'Port {{ openssh_map.config.port }}'
    - watch_in:
      - service: {{ openssh_map.service }}
