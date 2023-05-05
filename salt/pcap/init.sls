{% from 'pcap/config.map.jinja' import PCAPMERGED %}

include:
  - pcap.sostatus
{% if PCAPMERGED.enabled %}
  - pcap.enabled
{% else %}
  - pcap.disabled
{% endif %}
