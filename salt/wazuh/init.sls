{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

{%- set HOSTNAME = salt['grains.get']('host', '') %}
{% set VERSION = salt['pillar.get']('global:soversion', 'HH1.2.2') %}
{% set IMAGEREPO = salt['pillar.get']('global:imagerepo') %}
{% set MANAGER = salt['grains.get']('master') %}
# Add ossec group
ossecgroup:
  group.present:
    - name: ossec
    - gid: 945

# Add ossecm user
ossecm:
  user.present:
    - uid: 943
    - gid: 945
    - home: /nsm/wazuh
    - createhome: False
    - allow_uid_change: True
    - allow_gid_change: True

# Add ossecr user
ossecr:
  user.present:
    - uid: 944
    - gid: 945
    - home: /nsm/wazuh
    - createhome: False
    - allow_uid_change: True
    - allow_gid_change: True

# Add ossec user
ossec:
  user.present:
    - uid: 945
    - gid: 945
    - home: /nsm/wazuh
    - createhome: False
    - allow_uid_change: True
    - allow_gid_change: True

wazuhpkgs:
  pkg.installed:
    - skip_suggestions: False
    - pkgs:
      - wazuh-agent: 3.13.1-1
    - hold: True
    - update_holds: True

wazuhvarossecdir:
 file.directory:
    - name: /var/ossec
    - user: ossec
    - group: ossec
    - recurse:
      - user
      - group

# Add Wazuh agent conf
wazuhagentconf:
  file.managed:
    - name: /var/ossec/etc/ossec.conf
    - source: salt://wazuh/files/agent/ossec.conf
    - user: root
    - group: 945
    - template: jinja

wazuhdir:
 file.directory:
   - name: /nsm/wazuh
   - user: 945
   - group: 945
   - makedirs: True

# Wazuh agent registration script
wazuhagentregister:
  file.managed:
    - name: /usr/sbin/wazuh-register-agent
    - source: salt://wazuh/files/agent/wazuh-register-agent
    - user: root
    - group: root
    - mode: 755
    - template: jinja

# Whitelist script
wazuhmgrwhitelist:
   file.managed:
    - name: /usr/sbin/wazuh-manager-whitelist
    - source: salt://wazuh/files/wazuh-manager-whitelist
    - user: root
    - group: root
    - mode: 755
    - template: jinja

# Check to see if Wazuh API port is available
wazuhportavailable:
  cmd.run:
    - name: netstat -utanp | grep ":55000" | grep "LISTEN" | grep -qv docker && PROCESS=$(netstat -utanp | grep ":55000" | uniq) && echo "Another process ($PROCESS) appears to be using port 55000.  Please terminate this process, or reboot to ensure a clean state so that the Wazuh API can start properly." && exit 1 || exit 0

so-wazuh:
  docker_container.running:
    - image: {{ MANAGER }}:5000/{{ IMAGEREPO }}/so-wazuh:{{ VERSION }}
    - hostname: {{HOSTNAME}}-wazuh-manager
    - name: so-wazuh
    - detach: True
    - port_bindings:
      - 0.0.0.0:1514:1514/udp
      - 0.0.0.0:1514:1514/tcp
      - 0.0.0.0:1515:1515/tcp
      - 0.0.0.0:55000:55000
    - binds:
      - /nsm/wazuh:/var/ossec/data:rw

append_so-wazuh_so-status.conf:
  file.append:
    - name: /opt/so/conf/so-status/so-status.conf
    - text: so-wazuh

/opt/so/conf/wazuh:
  file.symlink:
    - target: /nsm/wazuh/etc

# Register the agent
registertheagent:
  cmd.run:
    - name: /usr/sbin/wazuh-register-agent
    - cwd: /
    - unless: ls /opt/so/conf/wazuh/initial_agent_registration.log

# Whitelist manager IP
whitelistmanager:
  cmd.run:
    - name: /usr/sbin/wazuh-manager-whitelist
    - cwd: /

wazuhagentservice:
  service.running:
    - name: wazuh-agent
    - enable: True

hidsruledir:
 file.directory:
   - name: /opt/so/rules/hids
   - user: 939
   - group: 939
   - makedirs: True

/opt/so/rules/hids/local_rules.xml:
  file.symlink:
    - target: /nsm/wazuh/etc/rules/local_rules.xml

/opt/so/rules/hids/ruleset:
  file.symlink:
    - target: /nsm/wazuh/ruleset

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}
