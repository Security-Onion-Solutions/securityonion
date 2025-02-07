{% set role = grains.id.split("_") | last %}
include:
  - setup.virt.setHostname
  - setup.virt.sominion
  - common.packages # python3-dnf-plugin-versionlock
{% if role in ['sensor', 'heavynode'] %}
  - sensor.vm.network
{% endif %}
  - setup.virt.setSalt
