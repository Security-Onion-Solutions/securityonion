soc_firewall_yaml:
  file.managed:
    - name: /opt/so/saltstack/default/salt/firewall/soc_firewall.yaml
    - source: salt://firewall/soc/soc_firewall.yaml.jinja
    - template: jinja
