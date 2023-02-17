{% from 'vars/globals.map.jinja' import GLOBALS %}

{% if GLOBALS.os != 'Rocky' %}    
saltpymodules:
  pkg.installed:
    - pkgs:
      {% if grains['oscodename'] == 'bionic' %}
      - python-m2crypto
      - python-docker
      {% elif grains['oscodename'] == 'focal' %}
      - python3-m2crypto
      - python3-docker
      {% endif %}
{% endif %}

salt_bootstrap:
  file.managed:
    - name: /usr/sbin/bootstrap-salt.sh
    - source: salt://salt/scripts/bootstrap-salt.sh
    - mode: 755
