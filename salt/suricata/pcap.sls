{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'suricata/map.jinja' import SURICATAMERGED %}

suripcapdir:
  file.directory:
    - name: /nsm/suripcap
    - user: 940
    - group: 939
    - mode: 755
    - makedirs: True


{% for i in range(1, SURICATAMERGED.config['af-packet'].threads) + 1) %}

suripcapthread{{i}}dir:
  file.directory:
    - name: /nsm/suripcap/{{i}}
    - user: 940
    - group: 939
    - mode: 755

{% endfor %}
