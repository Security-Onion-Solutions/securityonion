{% if grains['os'] != 'CentOS' %}    
saltpymodules:
  pkg.installed:
    - pkgs:
      - python-docker
      - python-m2crypto
{% endif %}

salt_bootstrap:
  file.managed:
    - name: /usr/sbin/bootstrap-salt.sh
    - source: salt://salt/scripts/bootstrap-salt.sh
    - mode: 755
