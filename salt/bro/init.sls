# Bro Salt State
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

# Sync the policies
bropolicysync:
  file.recurse:
    - name: /opt/so/conf/bro/policy
    - source: salt://bro/policy
    - user: 937
    - group: 939
    - template: jinja

# Sync local.bro
localbrosync:
  file.managed:
    - name: /opt/so/conf/bro/local.bro
    - source: salt://bro/files/local.bro
    - user: 937
    - group: 939
    - template: jinja

# Sync node.cfg
nodecfgsync:
  file.managed:
    - name: /opt/so/conf/bro/node.cfg
    - source: salt://bro/files/node.config
    - user: 937
    - group: 939
    - template: jinja

# Add the container

#so-bro:
#  dockerng.running:
#    - image: dockerrepo/so-bro:
#    - hostname: bro
#    - user: bro
#    - priviledged: true
#    - binds:
#      - /nsm/bro/logs:/nsm/bro/logs:rw
#      - /nsm/bro/spool:/nsm/bro/spool:rw
#      - /opt/so/conf/bro/etc:/opt/bro/etc:ro
#      - /opt/so/conf/bro/etc/node.cfg:/opt/bro/etc/node.cfg:ro
#      - /opt/so/conf/share/bro:/opt/bro/share/bro:ro
#    - network_mode: host
