{% from 'hypervisor/map.jinja' import HYPERVISORS %}

hypervisor_annotation:
  file.managed:
    - name: /opt/so/saltstack/default/salt/hypervisor/soc_hypervisor.yaml
    - source: salt://soc/dyanno/hypervisor/soc_hypervisor.yaml.jinja
    - template: jinja
    - defaults:
        HYPERVISORS: {{ HYPERVISORS }}

{% for role in HYPERVISORS %}
{%   for hypervisor in HYPERVISORS[role].keys() %}
hypervisor_host_directory_{{hypervisor}}:
  file.directory:
    - name: /opt/so/saltstack/local/salt/hypervisor/hosts/{{hypervisor}}
    - makedirs: True
    - user: socore
    - group: socore
    - recurse:
      - user
      - group
{%   endfor %}
{% endfor %}
