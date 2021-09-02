{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% set REMOVECURATORCRON = False %}
{% set TRUECLUSTER = salt['pillar.get']('elasticsearch:true_cluster', False) %}
{% set HOTWARM = salt['pillar.get']('elasticsearch:hot_warm_enabled', False) %}

{% if grains['role'] in ['so-eval', 'so-node', 'so-managersearch', 'so-heavynode', 'so-standalone', 'so-manager'] %}
  {% from 'elasticsearch/auth.map.jinja' import ELASTICAUTH with context %}
  {% from "curator/map.jinja" import CURATOROPTIONS with context %}
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

curconf:
  file.managed:
    - name: /opt/so/conf/curator/curator.yml
    - source: salt://curator/files/curator.yml
    - user: 934
    - group: 939
    - mode: 660
    - template: jinja

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
    - defaults:
        ELASTICCURL: {{ ELASTICAUTH.elasticcurl }}

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
  {% if CURATOROPTIONS.status == 'running' %}
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-curator:{{ VERSION }}
    - start: {{ CURATOROPTIONS.start }}
    - hostname: curator
    - name: so-curator
    - user: curator
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
  {% else %}
    - force: True
  {% endif %}

  {% if CURATOROPTIONS.manage_sostatus %}
append_so-curator_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-curator
    - unless: grep -q so-curator /opt/so/conf/so-status/so-status.conf

    {% if not CURATOROPTIONS.start %}
so-curator_so-status.disabled:
  file.comment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-curator$

      # need to remove cronjobs here since curator is disabled
      {% set REMOVECURATORCRON = True %}    
    {% else %}
delete_so-curator_so-status.disabled:
  file.uncomment:
    - name: /opt/so/conf/so-status/so-status.conf
    - regex: ^so-curator$

    {% endif %}

  {% else %}
delete_so-curator_so-status:
  file.line:
    - name: /opt/so/conf/so-status/so-status.conf
    - match: ^so-curator$
    - mode: delete

    # need to remove cronjobs here since curator is disabled
    {% set REMOVECURATORCRON = True %}

  {% endif %}

  {% if REMOVECURATORCRON %}
so-curatorcloseddeletecron:
  cron.absent:
    - name: /usr/sbin/so-curator-closed-delete > /opt/so/log/curator/cron-closed-delete.log 2>&1
    - user: root

so-curatorclosecron:
  cron.absent:
    - name: /usr/sbin/so-curator-close > /opt/so/log/curator/cron-close.log 2>&1
    - user: root

so-curatordeletecron:
  cron.absent:
    - name: /usr/sbin/so-curator-delete > /opt/so/log/curator/cron-delete.log 2>&1
    - user: root

  {% else %}

    {% if TRUECLUSTER is sameas true %}  
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
        {% if HOTWARM is sameas true %}
so-curatorclusterwarm:
  cron.present:
    - name: /usr/sbin/so-curator-cluster-warm > /opt/so/log/curator/cron-warm.log 2>&1
    - user: root
    - minute: '2'
    - hour: '*/1'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
        {% endif %}

    {% else %}
so-curatorcloseddeletecron:
  cron.present:
    - name: /usr/sbin/so-curator-closed-delete > /opt/so/log/curator/cron-closed-delete.log 2>&1
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

so-curatorclosecron:
  cron.present:
    - name: /usr/sbin/so-curator-close > /opt/so/log/curator/cron-close.log 2>&1
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

so-curatordeletecron:
  cron.present:
    - name: /usr/sbin/so-curator-delete > /opt/so/log/curator/cron-delete.log 2>&1
    - user: root
    - minute: '*/5'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'
  
    {% endif %}
  {% endif %}
{% endif %}

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
