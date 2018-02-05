# Bro Salt State
# Add Bro User
bro:
  user.present:
    - uid: 937
    - gid: 937
    - home: /home/bro

file.directory:
  - name: /opt/so/conf/bro
  - user: 937
  - group: 939

file.directory:
  - name: /opt/so/conf/bro/policy
  - user: 937
  - group: 939

# Add the container

so-bro:
  dockerng.running:
    - image: {{ dockerrepo }}/so-bro:{{ broversion }}
    - hostname: bro
    - user: bro
    - priviledged: true
    - binds:
      - /nsm/bro/logs:/nsm/bro/logs:rw
      - /nsm/bro/spool:/nsm/bro/spool:rw
      - /opt/so/conf/bro/etc:/opt/bro/etc:ro
      - /opt/so/conf/bro/etc/node.cfg:/opt/bro/etc/node.cfg:ro
      - /opt/so/conf/share/bro:/opt/bro/share/bro:ro
    - network_mode: host

# Add Bro cron
