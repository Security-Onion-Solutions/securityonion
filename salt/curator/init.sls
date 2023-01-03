# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}
{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from "curator/map.jinja" import CURATOROPTIONS %}
{% from "curator/map.jinja" import CURATORMERGED %}
{% set REMOVECURATORCRON = False %}

# Curator
# Create the group
curatorgroup:
  group.present:
    - name: curator
    - gid: 934

# Add user
curator:
  user.present:
    - uid: 934
    - gid: 934
    - home: /opt/so/conf/curator
    - createhome: False

# Create the log directory
curactiondir:
  file.directory:
    - name: /opt/so/conf/curator/action
    - user: 934
    - group: 939
    - makedirs: True

curlogdir:
  file.directory:
    - name: /opt/so/log/curator
    - user: 934
    - group: 939

actionconfs:
  file.recurse:
    - name: /opt/so/conf/curator/action
    - source: salt://curator/files/action
    - user: 934
    - group: 939
    - template: jinja
    - defaults:
        CURATORMERGED: {{ CURATORMERGED }}
        

curconf:
  file.managed:
    - name: /opt/so/conf/curator/curator.yml
    - source: salt://curator/files/curator.yml
    - user: 934
    - group: 939
    - mode: 660
    - template: jinja
    - show_changes: False

curcloseddel:
  file.managed:
    - name: /usr/sbin/so-curator-closed-delete
    - source: salt://curator/files/bin/so-curator-closed-delete
    - user: 934
    - group: 939
    - mode: 755

curcloseddeldel:
  file.managed:
    - name: /usr/sbin/so-curator-closed-delete-delete
    - source: salt://curator/files/bin/so-curator-closed-delete-delete
    - user: 934
    - group: 939
    - mode: 755
    - template: jinja

curclose:
  file.managed:
    - name: /usr/sbin/so-curator-close
    - source: salt://curator/files/bin/so-curator-close
    - user: 934
    - group: 939
    - mode: 755
    - template: jinja

curdel:
  file.managed:
    - name: /usr/sbin/so-curator-delete
    - source: salt://curator/files/bin/so-curator-delete
    - user: 934
    - group: 939
    - mode: 755

curclusterclose: 
  file.managed:
    - name: /usr/sbin/so-curator-cluster-close
    - source: salt://curator/files/bin/so-curator-cluster-close
    - user: 934
    - group: 939
    - mode: 755
    - template: jinja

curclusterdelete: 
  file.managed:
    - name: /usr/sbin/so-curator-cluster-delete
    - source: salt://curator/files/bin/so-curator-cluster-delete
    - user: 934
    - group: 939
    - mode: 755
    - template: jinja

curclustercwarm: 
  file.managed:
    - name: /usr/sbin/so-curator-cluster-warm
    - source: salt://curator/files/bin/so-curator-cluster-warm
    - user: 934
    - group: 939
    - mode: 755
    - template: jinja

so-curator:
  docker_container.{{ CURATOROPTIONS.status }}:
    - image: {{ GLOBALS.registry_host }}:5000/{{ GLOBALS.image_repo }}/so-curator:{{ GLOBALS.so_version }}
    - start: {{ CURATOROPTIONS.start }}
    - hostname: curator
    - name: so-curator
    - user: curator
    - networks:
      - sosbridge: []
    - interactive: True
    - tty: True
    - binds:
      - /opt/so/conf/curator/curator.yml:/etc/curator/config/curator.yml:ro
      - /opt/so/conf/curator/action/:/etc/curator/action:ro
      - /opt/so/log/curator:/var/log/curator:rw
    - require:
      - file: actionconfs
      - file: curconf
      - file: curlogdir

so-curatorclusterclose:
  cron.present:
    - name: /usr/sbin/so-curator-cluster-close > /opt/so/log/curator/cron-close.log 2>&1
    - user: root
    - minute: '2'
    - hour: '*/1'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

so-curatorclusterdelete:
  cron.present:
    - name: /usr/sbin/so-curator-cluster-delete > /opt/so/log/curator/cron-delete.log 2>&1
    - user: root
    - minute: '2'
    - hour: '*/1'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

so-curatorclusterwarm:
  cron.present:
    - name: /usr/sbin/so-curator-cluster-warm > /opt/so/log/curator/cron-warm.log 2>&1
    - user: root
    - minute: '2'
    - hour: '*/1'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
