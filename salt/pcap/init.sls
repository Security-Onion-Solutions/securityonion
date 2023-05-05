{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'pcap/config.map.jinja' import PCAPMERGED %}

include:
{% if PCAPMERGED.enabled and GLOBALS.role != 'so-import'%}
  - pcap.enabled
{% elif GLOBALS.role == 'so-import' %}
  - pcap.config
  - pcap.disabled
{% else %}
  - pcap.disabled
{% endif %}
