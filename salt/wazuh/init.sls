{%- set HOSTNAME = salt['grains.get']('host', '') %}

#vm.max_map_count:
#  sysctl.present:
#    - value: 262144

# Add ossec Group
ossecgroup:
  group.present:
    - name: ossec
    - gid: 945

# Add ossecm user
ossecm:
  user.present:
    - uid: 943
    - gid: 945
    - home: /opt/so/wazuh
    - createhome: False

# Add ossecr user
ossecr:
  user.present:
    - uid: 944
    - gid: 945
    - home: /opt/so/wazuh
    - createhome: False

# Add ossec user
ossec:
  user.present:
    - uid: 945
    - gid: 945
    - home: /opt/so/wazuh
    - createhome: False

# Add wazuh agent
wazuhpkgs:
 pkg.installed:
   - skip_suggestions: False
   - pkgs:
     - wazuh-agent

# Add Wazuh agent conf
eslog4jfile:
  file.managed:
    - name: /var/ossec/etc/ossec.conf
    - source: salt://wazuh/files/agent/ossec.conf
    - user: 0
    - group: 945
    - template: jinja

so-wazuh:
  docker_container.running:
    - image: soshybridhunter/so-wazuh:HH1.0.5
    - hostname: {{HOSTNAME}}-wazuh-manager
    - name: so-wazuh
    - detach: True
    - port_bindings:
      - 0.0.0.0:1514:1514/udp
      - 0.0.0.0:1514:1514/tcp
      - 0.0.0.0:55000:55000
    - binds:
      - /opt/so/wazuh/:/var/ossec/data/:rw

