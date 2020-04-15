{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.2.1') %}
{% set MASTER = salt['grains.get']('master') %}
{% if grains['role'] == 'so-node' or grains['role'] == 'so-eval' %}
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

curcloseconf:
  file.managed:
    - name: /opt/so/conf/curator/action/close.yml
    - source: salt://curator/files/action/close.yml
    - user: 934
    - group: 939
    - template: jinja

curdelconf:
  file.managed:
    - name: /opt/so/conf/curator/action/delete.yml
    - source: salt://curator/files/action/delete.yml
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
   - name: /usr/sbin/so-curator-closed-delete
   - user: root
   - minute: '*'
   - hour: '*'
   - daymonth: '*'
   - month: '*'
   - dayweek: '*'

so-curatorclosecron:
 cron.present:
   - name: /usr/sbin/so-curator-close
   - user: root
   - minute: '*'
   - hour: '*'
   - daymonth: '*'
   - month: '*'
   - dayweek: '*'

so-curatordeletecron:
 cron.present:
   - name: /usr/sbin/so-curator-delete
   - user: root
   - minute: '*'
   - hour: '*'
   - daymonth: '*'
   - month: '*'
   - dayweek: '*'

so-curator:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-curator:{{ VERSION }}
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
