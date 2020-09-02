{% set show_top = salt['state.show_top']() %}
{% set top_states = show_top.values() | join(', ') %}

{% if 'yum' in top_states %}

yumconf:
  file.managed:
    - name: /etc/yum.conf
    - source: salt://yum/etc/yum.conf.jinja
    - mode: 644
    - template: jinja

{% endif %}