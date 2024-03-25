{% if grains.oscodename == 'focal' %}
saltpymodules:
  pkg.installed:
    - pkgs:
      - python3-docker
{% endif %}

salt_bootstrap:
  file.managed:
    - name: /usr/sbin/bootstrap-salt.sh
    - source: salt://salt/scripts/bootstrap-salt.sh
    - mode: 755
    - show_changes: False
