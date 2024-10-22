hypervisor_annotation:
  file.managed:
    - name: /opt/so/saltstack/default/salt/hypervisor/soc_hypervisor.yaml
    - source: salt://soc/dynamic_annotations/hypervisor/soc_hypervisor.yaml.jinja
    - template: jinja
