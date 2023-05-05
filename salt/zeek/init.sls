{% from 'vars/globals.map.jinja' import GLOBALS %}
{% from 'zeek/config.map.jinja' import ZEEKMERGED %}

include:
{% if ZEEKMERGED.enabled and GLOBALS.role != 'so-import'%}
  - zeek.enabled
{% elif GLOBALS.role == 'so-import' %}
  - zeek.config
  - zeek.disabled
{% else %}
  - zeek.disabled
{% endif %}
