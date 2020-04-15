# Copyright 2014,2015,2016,2017,2018 Security Onion Solutions, LLC

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}
{% if grains['role'] == 'so-master' %}

{% set esalert = salt['pillar.get']('master:elastalert', '1') %}
{% set esip = salt['pillar.get']('master:mainip', '') %}
{% set esport = salt['pillar.get']('master:es_port', '') %}


{% elif grains['role'] in ['so-eval','so-mastersearch'] %}

{% set esalert = salt['pillar.get']('master:elastalert', '1') %}
{% set esip = salt['pillar.get']('master:mainip', '') %}
{% set esport = salt['pillar.get']('master:es_port', '') %}


{% elif grains['role'] == 'so-node' %}

{% set esalert = salt['pillar.get']('node:elastalert', '0') %}

{% endif %}

# Elastalert
{% if esalert == 1 %}

# Create the group
elastagroup:
  group.present:
    - name: elastalert
    - gid: 933

# Add user
elastalert:
  user.present:
    - uid: 933
    - gid: 933
    - home: /opt/so/conf/elastalert
    - createhome: False

elastalogdir:
  file.directory:
    - name: /opt/so/log/elastalert
    - user: 933
    - group: 939
    - makedirs: True

elastarules:
  file.directory:
    - name: /opt/so/rules/elastalert
    - user: 933
    - group: 939
    - makedirs: True

elastaconfdir:
  file.directory:
    - name: /opt/so/conf/elastalert
    - user: 933
    - group: 939
    - makedirs: True

elastasomodulesdir:
  file.directory:
    - name: /opt/so/conf/elastalert/modules/so
    - user: 933
    - group: 939
    - makedirs: True

elastacustmodulesdir:
  file.directory:
    - name: /opt/so/conf/elastalert/modules/custom
    - user: 933
    - group: 939
    - makedirs: True

elastasomodulesync:
  file.recurse:
    - name: /opt/so/conf/elastalert/modules/so
    - source: salt://elastalert/files/modules/so
    - user: 933
    - group: 939
    - makedirs: True

elastarulesync:
  file.recurse:
    - name: /opt/so/rules/elastalert
    - source: salt://elastalert/files/rules/so
    - user: 933
    - group: 939
    - template: jinja

elastaconf:
  file.managed:
    - name: /opt/so/conf/elastalert/elastalert_config.yaml
    - source: salt://elastalert/files/elastalert_config.yaml
    - user: 933
    - group: 939
    - template: jinja

so-elastalert:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-elastalert:{{ VERSION }}
    - hostname: elastalert
    - name: so-elastalert
    - user: elastalert
    - detach: True
    - binds:
      - /opt/so/rules/elastalert:/etc/elastalert/rules/:ro
      - /opt/so/log/elastalert:/var/log/elastalert:rw
      - /opt/so/conf/elastalert/modules/:/opt/elastalert/modules/:ro
      - /opt/so/conf/elastalert/elastalert_config.yaml:/etc/elastalert/conf/elastalert_config.yaml:ro
    - environment:
      - ELASTICSEARCH_HOST: {{ esip }}
      - ELASTICSEARCH_PORT: {{ esport }}
      - ELASTALERT_CONFIG: /etc/elastalert/conf/elastalert_config.yaml
      - ELASTALERT_SUPERVISOR_CONF: /etc/elastalert/conf/elastalert_supervisord.conf
      - RULES_DIRECTORY: /etc/elastalert/rules/
      - LOG_DIR: /var/log/elastalert

{% endif %}
