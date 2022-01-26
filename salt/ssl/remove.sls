# Trust the CA
trusttheca:
  file.absent:
    - name: /etc/ssl/certs/intca.crt

removefbcertdir:
  file.absent:
    - name: /etc/pki/filebeat.crt 
    - onlyif: "[ -d /etc/pki/filebeat.crt ]"

removefbp8dir:
  file.absent:
    - name: /etc/pki/filebeat.p8 
    - onlyif: "[ -d /etc/pki/filebeat.p8 ]"

removeesp12dir:
  file.absent:
    - name: /etc/pki/elasticsearch.p12
    - onlyif: "[ -d /etc/pki/elasticsearch.p12 ]"
    
influxdb_key:
  file.absent:
    - name: /etc/pki/influxdb.key

influxdb_crt:
  file.absent:
    - name: /etc/pki/influxdb.crt

{% if grains['role'] in ['so-manager', 'so-eval', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-fleet', 'so-receiver'] %}
redis_key:
  file.absent:
    - name: /etc/pki/redis.key

redis_crt:
  file.absent:
    - name: /etc/pki/redis.crt
{% endif %}

{% if grains['role'] in ['so-manager', 'so-eval', 'so-helix', 'so-managersearch', 'so-standalone', 'so-import', 'so-heavynode', 'so-receiver'] %}
etc_filebeat_key:
  file.absent:
    - name: /etc/pki/filebeat.key

etc_filebeat_crt:
  file.absent:
    - name: /etc/pki/filebeat.crt

  {% if grains.role not in ['so-heavynode', 'so-receiver'] %}
filebeatdir:
  file.absent:
    - name: /opt/so/saltstack/local/salt/filebeat/files

registry_key:
  file.absent:
    - name: /etc/pki/registry.key

registry_crt:
  file.absent:
    - name: /etc/pki/registry.crt

  {% endif %}

  {% if grains.role not in ['so-receiver'] %}
/etc/pki/elasticsearch.key:
  file.absent: []

/etc/pki/elasticsearch.crt:
  file.absent: []

remove_elasticsearch.p12:
  file.absent:
    - name: /etc/pki/elasticsearch.p12

managerssl_key:
  file.absent:
    - name: /etc/pki/managerssl.key

managerssl_crt:
  file.absent:
    - name: /etc/pki/managerssl.crt

  {% endif %}

fleet_key:
  file.absent:
    - name: /etc/pki/fleet.key

fleet_crt:
  file.absent:
    - name: /etc/pki/fleet.crt

{% endif %}

{% if grains['role'] in ['so-sensor', 'so-manager', 'so-node', 'so-eval', 'so-helix', 'so-managersearch', 'so-heavynode', 'so-fleet', 'so-standalone', 'so-import', 'so-receiver'] %}
   
fbcertdir:
  file.absent:
    - name: /opt/so/conf/filebeat/etc/pki
    
{% endif %}

{% if grains['role'] == 'so-fleet' %}

managerssl_key:
  file.absent:
    - name: /etc/pki/managerssl.key

managerssl_crt:
  file.absent:
    - name: /etc/pki/managerssl.crt

fleet_key:
  file.absent:
    - name: /etc/pki/fleet.key

fleet_crt:
  file.absent:
    - name: /etc/pki/fleet.crt

{% endif %}

{% if grains['role'] == 'so-node' %}

/etc/pki/elasticsearch.key:
  file.absent: []

/etc/pki/elasticsearch.crt:
  file.absent: []

remove_elastic.p12:
  file.absent:
    - name: /etc/pki/elasticsearch.p12

{%- endif %}
