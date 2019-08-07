# Bro Salt State
# Add Bro group
brogroup:
  group.present:
    - name: bro
    - gid: 937

# Add Bro User
bro:
  user.present:
    - uid: 937
    - gid: 937
    - home: /home/bro

# Create some directories
bropolicydir:
  file.directory:
    - name: /opt/so/conf/bro/policy
    - user: 937
    - group: 939
    - makedirs: True

# Bro Log Directory
brologdir:
  file.directory:
    - name: /nsm/bro/logs
    - user: 937
    - group: 939
    - makedirs: True

# Bro Spool Directory
brospooldir:
  file.directory:
    - name: /nsm/bro/spool/manager
    - user: 937
    - makedirs: true

brosfafincompletedir:
  file.directory:
    - name: /nsm/faf/files/incomplete
    - user: 937
    - makedirs: true

brosfafcompletedir:
  file.directory:
    - name: /nsm/faf/files/complete
    - user: 937
    - makedirs: true

# Sync the policies
bropolicysync:
  file.recurse:
    - name: /opt/so/conf/bro/policy
    - source: salt://bro/policy
    - user: 937
    - group: 939
    - template: jinja

# Sync node.cfg
nodecfgsync:
  file.managed:
    - name: /opt/so/conf/bro/node.cfg
    - source: salt://bro/files/node.cfg
    - user: 937
    - group: 939
    - template: jinja

plcronscript:
  file.managed:
    - name: /usr/local/bin/packetloss.sh
    - source: salt://bro/cron/packetloss.sh
    - mode: 755

/usr/local/bin/packetloss.sh:
  cron.present:
    - user: root
    - minute: '*/10'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

# Sync local.bro
{% if salt['pillar.get']('static:broversion', '') == 'COMMUNITY' %}
localbrosync:
  file.managed:
    - name: /opt/so/conf/bro/local.bro
    - source: salt://bro/files/local.bro.community
    - user: 937
    - group: 939
    - template: jinja

so-communitybroimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false soshybridhunter/so-communitybro:HH1.0.3

so-bro:
  docker_container.running:
    - require:
      - so-communitybroimage
    - image: soshybridhunter/so-communitybro:HH1.0.3
    - privileged: True
    - binds:
      - /nsm/bro/logs:/nsm/bro/logs:rw
      - /nsm/bro/spool:/nsm/bro/spool:rw
      - /opt/so/conf/bro/local.bro:/opt/bro/share/bro/site/local.bro:ro
      - /opt/so/conf/bro/node.cfg:/opt/bro/etc/node.cfg:ro
      - /opt/so/conf/bro/policy/securityonion:/opt/bro/share/bro/policy/securityonion:ro
      - /opt/so/conf/bro/policy/custom:/opt/bro/share/bro/policy/custom:ro
      - /opt/so/conf/bro/policy/intel:/opt/bro/share/bro/policy/intel:rw
    - network_mode: host
    - watch:
      - file: /opt/so/conf/bro/local.bro
      - file: /opt/so/conf/bro/node.cfg
      - file: /opt/so/conf/bro/policy

{% else %}
localbrosync:
  file.managed:
    - name: /opt/so/conf/bro/local.bro
    - source: salt://bro/files/local.bro
    - user: 937
    - group: 939
    - template: jinja

so-broimage:
 cmd.run:
   - name: docker pull --disable-content-trust=false soshybridhunter/so-bro:HH1.1.1

so-bro:
  docker_container.running:
    - require:
      - so-broimage
    - image: soshybridhunter/so-bro:HH1.1.1
    - privileged: True
    - binds:
      - /nsm/bro/logs:/nsm/bro/logs:rw
      - /nsm/bro/spool:/nsm/bro/spool:rw
      - /opt/so/conf/bro/local.bro:/opt/bro/share/bro/site/local.bro:ro
      - /opt/so/conf/bro/node.cfg:/opt/bro/etc/node.cfg:ro
      - /opt/so/conf/bro/policy/securityonion:/opt/bro/share/bro/policy/securityonion:ro
      - /opt/so/conf/bro/policy/custom:/opt/bro/share/bro/policy/custom:ro
      - /opt/so/conf/bro/policy/intel:/opt/bro/share/bro/policy/intel:rw
    - network_mode: host
    - watch:
      - file: /opt/so/conf/bro/local.bro
      - file: /opt/so/conf/bro/node.cfg
      - file: /opt/so/conf/bro/policy


{% endif %}
