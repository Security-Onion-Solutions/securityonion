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
    - name: /nsm/bro/spool
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
    - source: salt://bro/files/node.cfg
    - user: 937
    - group: 939
    - template: jinja

# Add the container

so-bro:
  dockerng.running:
    - image: toosmooth/so-bro:test2
    - user: bro
    - priviledged: true
    - binds:
      - /nsm/bro/logs:/nsm/bro/logs:rw
      - /nsm/bro/spool:/nsm/bro/spool:rw
      - /opt/so/conf/bro/local.bro:/opt/bro/share/bro/site/local.bro:ro
      - /opt/so/conf/bro/node.cfg:/opt/bro/etc/node.cfg:ro
      - /opt/so/conf/bro/policy:/opt/bro/share/bro/policy:ro
    - network_mode: host
