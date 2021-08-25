{% if grains['os'] != 'CentOS' %}    
saltpymodules:
  pkg.installed:
    - pkgs:
      - python3-docker
      - python3-m2crypto
{% endif %}

salt_bootstrap:
  file.managed:
    - name: /usr/sbin/bootstrap-salt.sh
    - source: salt://salt/scripts/bootstrap-salt.sh
    - mode: 755

{% if grains.os == 'CentOS'  %}
remove_salt-2019-2-5.repo:
  file.absent:
    - name: /etc/yum.repos.d/salt-2019-2-5.repo
{% endif %}
