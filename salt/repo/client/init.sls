{% from 'repo/client/map.jinja' import ABSENTFILES with context %}
{% from 'repo/client/map.jinja' import REPOPATH with context %}
{% set ISAIRGAP = salt['pillar.get']('global:airgap', False) %}
{% set managerupdates = salt['pillar.get']('global:managerupdate', '0') %}
{% set role = grains.id.split('_') | last %}

# from airgap state
{% if ISAIRGAP and grains.os == 'CentOS' %}
{% set MANAGER = salt['grains.get']('master') %}
airgapyum:
  file.managed:
    - name: /etc/yum/yum.conf
    - source: salt://repo/client/files/centos/airgap/yum.conf

airgap_repo:
  pkgrepo.managed:
    - humanname: Airgap Repo
    - baseurl: https://{{ MANAGER }}/repo
    - gpgcheck: 0
    - sslverify: 0

{% endif %}

# from airgap and common
{% if ABSENTFILES|length > 0%}
  {% for file in ABSENTFILES  %}
{{ file }}:
  file.absent:
    - name: {{ REPOPATH }}{{ file }}
    - onchanges_in:
      - module: cleanyum
  {% endfor %}
{% endif %}

# from common state
# Remove default Repos
{% if grains['os'] == 'CentOS' %}
repair_yumdb:
  cmd.run:
    - name: 'mv -f /var/lib/rpm/__db* /tmp && yum clean all'
    - onlyif:
      - 'yum check-update 2>&1 | grep "Error: rpmdb open failed"'

crsynckeys:
  file.recurse:
    - name: /etc/pki/rpm_gpg
    - source: salt://repo/client/files/centos/keys/

{% if not ISAIRGAP %}
crsecurityonionrepo:
  file.managed:
    {% if role in ['eval', 'standalone', 'import', 'manager', 'managersearch'] or managerupdates == 0 %}
    - name: /etc/yum.repos.d/securityonion.repo
    - source: salt://repo/client/files/centos/securityonion.repo
    {% else %}
    - name: /etc/yum.repos.d/securityonioncache.repo
    - source: salt://repo/client/files/centos/securityonioncache.repo
    {% endif %}
    - mode: 644

yumconf:
  file.managed:
    - name: /etc/yum.conf
    - source: salt://repo/client/files/centos/yum.conf.jinja
    - mode: 644
    - template: jinja
    - show_changes: False

cleanairgap:
  file.absent:
    - name: /etc/yum.repos.d/airgap_repo.repo
{% endif %}

cleanyum:
  cmd.run:
    - name: 'yum clean metadata'
    - onchanges:
{% if ISAIRGAP %}
      - file: airgapyum
      - pkgrepo: airgap_repo
{% else %}
      - file: crsecurityonionrepo
      - file: yumconf
{% endif %}

{% endif %}
