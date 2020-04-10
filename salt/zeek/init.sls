{% set VERSION = salt['pillar.get']('static:soversion', 'HH1.1.4') %}
{% set MASTER = salt['grains.get']('master') %}
{% set BPF_ZEEK = salt['pillar.get']('zeek:bpf', {}) %}
{% set BPF_STATUS = 0  %}
{% set INTERFACE = salt['pillar.get']('sensor:interface', 'bond0') %}

{% import_yaml 'zeek/defaults.yml' as ZEEKDEFAULTS %}
{% set ZEEK = salt['pillar.get']('zeek', default=ZEEKDEFAULTS.zeek, merge=True) %}

# Zeek Salt State

# Add Zeek group
zeekgroup:
  group.present:
    - name: zeek
    - gid: 937

# Add Zeek User
zeek:
  user.present:
    - uid: 937
    - gid: 937
    - home: /home/zeek

# Create some directories
zeekpolicydir:
  file.directory:
    - name: /opt/so/conf/zeek/policy
    - user: 937
    - group: 939
    - makedirs: True

# Zeek Log Directory
zeeklogdir:
  file.directory:
    - name: /nsm/zeek/logs
    - user: 937
    - group: 939
    - makedirs: True

# Zeek Spool Directory
zeekspooldir:
  file.directory:
    - name: /nsm/zeek/spool/manager
    - user: 937
    - makedirs: true

# Zeek extracted
zeekextractdir:
  file.directory:
    - name: /nsm/zeek/extracted
    - user: 937
    - group: 939
    - makedirs: True

zeekextractcompletedir:
  file.directory:
    - name: /nsm/zeek/extracted/complete
    - user: 937
    - makedirs: true

# Sync the policies
zeekpolicysync:
  file.recurse:
    - name: /opt/so/conf/zeek/policy
    - source: salt://zeek/policy
    - user: 937
    - group: 939
    - template: jinja

zeekctlcfg:
  file.managed:
    - name: /opt/so/conf/zeek/zeekctl.cfg
    - source: salt://zeek/files/zeekctl.cfg.jinja
    - user: 937
    - group: 939
    - template: jinja
    - defaults:
        ZEEKCTL: {{ ZEEK.zeekctl | tojson }}

# Sync node.cfg
nodecfgsync:
  file.managed:
    - name: /opt/so/conf/zeek/node.cfg
    - source: salt://zeek/files/node.cfg
    - user: 937
    - group: 939
    - template: jinja

zeekcleanscript:
  file.managed:
    - name: /usr/local/bin/zeek_clean
    - source: salt://zeek/cron/zeek_clean
    - mode: 755

/usr/local/bin/zeek_clean:
  cron.present:
    - user: root
    - minute: '*'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

plcronscript:
  file.managed:
    - name: /usr/local/bin/packetloss.sh
    - source: salt://zeek/cron/packetloss.sh
    - mode: 755

zeekpacketlosscron:
  cron.present:
    - name: /usr/local/bin/packetloss.sh
    - user: root
    - minute: '*/10'
    - hour: '*'
    - daymonth: '*'
    - month: '*'
    - dayweek: '*'

# BPF compilation and configuration
{% if BPF_ZEEK %}
   {% set BPF_CALC = salt['cmd.script']('/usr/sbin/so-bpf-compile', INTERFACE + ' ' + BPF_ZEEK|join(" "),cwd='/root') %}
   {% if BPF_CALC['stderr'] == "" %}
       {% set BPF_STATUS = 1  %}
  {% else  %}
zeekbpfcompilationfailure:
  test.configurable_test_state:
    - changes: False
    - result: False
    - comment: "BPF Syntax Error - Discarding Specified BPF"
   {% endif %}
{% endif %}

zeekbpf:
  file.managed:
    - name: /opt/so/conf/zeek/bpf
    - user: 940
    - group: 940
{% if BPF_STATUS %}
    - contents_pillar: zeek:bpf
{% else %}
    - contents:
      - "ip or not ip"
{% endif %}

localzeeksync:
  file.managed:
    - name: /opt/so/conf/zeek/local.zeek
    - source: salt://zeek/files/local.zeek
    - user: 937
    - group: 939
    - template: jinja

so-zeek:
  docker_container.running:
    - image: {{ MASTER }}:5000/soshybridhunter/so-zeek:{{ VERSION }}
    - privileged: True
    - binds:
      - /nsm/zeek/logs:/nsm/zeek/logs:rw
      - /nsm/zeek/spool:/nsm/zeek/spool:rw
      - /nsm/zeek/extracted:/nsm/zeek/extracted:rw
      - /opt/so/conf/zeek/local.zeek:/opt/zeek/share/zeek/site/local.zeek:ro
      - /opt/so/conf/zeek/node.cfg:/opt/zeek/etc/node.cfg:ro
      - /opt/so/conf/zeek/zeekctl.cfg:/opt/zeek/etc/zeekctl.cfg:ro
      - /opt/so/conf/zeek/policy/securityonion:/opt/zeek/share/zeek/policy/securityonion:ro
      - /opt/so/conf/zeek/policy/custom:/opt/zeek/share/zeek/policy/custom:ro
      - /opt/so/conf/zeek/policy/cve-2020-0601:/opt/zeek/share/zeek/policy/cve-2020-0601:ro
      - /opt/so/conf/zeek/policy/intel:/opt/zeek/share/zeek/policy/intel:rw
      - /opt/so/conf/zeek/bpf:/opt/zeek/etc/bpf:ro 
    - network_mode: host
    - watch:
      - file: /opt/so/conf/zeek/local.zeek
      - file: /opt/so/conf/zeek/node.cfg
      - file: /opt/so/conf/zeek/zeekctl.cfg
      - file: /opt/so/conf/zeek/policy
      - file: /opt/so/conf/zeek/bpf
