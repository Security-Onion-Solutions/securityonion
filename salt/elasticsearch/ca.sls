# Move our new CA over so Elastic and Logstash can use SSL with the internal CA
catrustdir:
  file.directory:
    - name: /opt/so/conf/ca
    - user: 939
    - group: 939
    - makedirs: True

{%   if GLOBALS.is_manager %}
# We have to add the Manager CA to the CA list
cascriptsync:
  cmd.script:
    - source: salt://elasticsearch/tools/sbin_jinja/so-catrust
    - template: jinja
    - defaults:
        GLOBALS: {{ GLOBALS }}
{%   endif %}

{% if grains.role in ['so-manager', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import', 'so-searchnode'] %}
cacertz:
  file.managed:
    - name: /opt/so/conf/ca/cacerts
    - source: salt://elasticsearch/cacerts
    - user: 939
    - group: 939

capemz:
  file.managed:
    - name: /opt/so/conf/ca/tls-ca-bundle.pem
    - source: salt://elasticsearch/tls-ca-bundle.pem
    - user: 939
    - group: 939
{% endif %}
