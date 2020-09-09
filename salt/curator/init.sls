{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'curator' in top_states %}

{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
{% if grains['role'] in ['so-eval', 'so-node', 'so-managersearch', 'so-heavynode', 'so-standalone'] %}
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

curclose:
  file.managed:
    - name: /usr/sbin/so-curator-close
    - source: salt://curator/files/bin/so-curator-close
    - user: 934
    - group: 939
    - mode: 755

curdel:
  file.managed:
    - name: /usr/sbin/so-curator-delete
    - source: salt://curator/files/bin/so-curator-delete
    - user: 934
    - group: 939
    - mode: 755

so-curatorcloseddeletecron:
 cron.present:
   - name: /usr/sbin/so-curator-closed-delete > /opt/so/log/curator/cron-closed-delete.log 2>&1
   - user: root
   - minute: '*'
   - hour: '*'
   - daymonth: '*'
   - month: '*'
   - dayweek: '*'

so-curatorclosecron:
 cron.present:
   - name: /usr/sbin/so-curator-close > /opt/so/log/curator/cron-close.log 2>&1
   - user: root
   - minute: '*'
   - hour: '*'
   - daymonth: '*'
   - month: '*'
   - dayweek: '*'

so-curatordeletecron:
 cron.present:
   - name: /usr/sbin/so-curator-delete > /opt/so/log/curator/cron-delete.log 2>&1
   - user: root
   - minute: '*'
   - hour: '*'
   - daymonth: '*'
   - month: '*'
   - dayweek: '*'

so-curator:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-curator:{{ VERSION }}
    - hostname: curator
    - name: so-curator
    - user: curator
    - interactive: True
    - tty: True
    - binds:
      - /opt/so/conf/curator/curator.yml:/etc/curator/config/curator.yml:ro
      - /opt/so/conf/curator/action/:/etc/curator/action:ro
      - /opt/so/log/curator:/var/log/curator:rw
# Begin Curator Cron Jobs

# Close
# Delete
# Hot Warm
# Segment Merge

# End Curator Cron Jobs
{% endif %}

{% else %}

curator_state_not_allowed:
  test.fail_without_changes:
    - name: curator_state_not_allowed

{% endif %}