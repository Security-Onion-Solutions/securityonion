soc_hypervisor_pillar:
  file.managed:
    - name: /opt/so/saltstack/local/pillar/hypervisor/soc_hypervisor.sls
    - source: salt://hypervisor/pillar.map.jinja
    - template: jinja
