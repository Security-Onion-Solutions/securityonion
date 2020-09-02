{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'salt.master' in top_states %}

salt_master_package:
  pkg.installed:
    - pkgs:
      - salt
      - salt-master
    - hold: True

salt_master_service:
  service.running:
    - name: salt-master
    - enable: True

{% endif %}