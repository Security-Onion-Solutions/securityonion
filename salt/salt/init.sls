# Create a state directory

statedir:
  file.directory:
    - name: /opt/so/state
    - user: 939
    - group: 939
    - makedirs: True

salttmp:
  file.directory:
    - name: /opt/so/tmp
    - user: 939
    - group: 939
    - makedirs: True

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
