{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'suricata/map.jinja' import SURICATAMERGED %}

# This directory needs to exist regardless of whether SURIPCAP is enabled or not, in order for
# Sensoroni to be able to look at old Suricata PCAP data
suripcapdir:
  file.directory:
    - name: /nsm/suripcap
    - user: 940
    - group: 939
    - mode: 775
    - makedirs: True

{%   if GLOBALS.pcap_engine in ["SURICATA", "TRANSITION"] %}

{# there should only be 1 interface in af-packet so we can just reference the first list item #}
{% for i in range(1, SURICATAMERGED.config['af-packet'][0].threads + 1) %}

suripcapthread{{i}}dir:
  file.directory:
    - name: /nsm/suripcap/{{i}}
    - user: 940
    - group: 939
    - mode: 775

{% endfor %}

{%   endif %}
