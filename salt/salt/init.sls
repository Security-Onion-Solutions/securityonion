

{% if grains['os'] != 'CentOS' %}    
saltpymodules:
  pkg.installed:
    - pkgs:
      - python-docker
      - python-m2crypto
  {% endif %}


salt_minion_service:
  service.running:
    - name: salt-minion
    - enable: True
