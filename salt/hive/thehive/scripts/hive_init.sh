#!/bin/bash
{%- set MASTERIP = salt['pillar.get']('static:masterip', '') %}
{%- set HIVEUSER = salt['pillar.get']('static:hiveuser', '') %}
{%- set HIVEPASSWORD = salt['pillar.get']('static:hivepassword', '') %}
{%- set HIVEKEY = salt['pillar.get']('static:hivekey', '') %}

hive_init(){
    sleep 60
    HIVE_IP="{{MASTERIP}}"
    HIVE_USER="{{HIVEUSER}}"
    HIVE_PASSWORD="{{HIVEPASSWORD}}"
    SOCTOPUS_CONFIG="/opt/so/saltstack/salt/soctopus/files/SOCtopus.conf"

    # Migrate DB
    curl -v -k -XPOST "https://$HIVE_IP:/thehive/api/maintenance/migrate"

    # Generate unique ID for apikey
    HIVE_KEY="{{HIVEKEY}}"

    # Create intial TheHive user
    curl -v -k "https://$HIVE_IP/thehive/api/user" -H "Content-Type: application/json" -d "{\"login\" : \"$HIVE_USER\",\"name\" : \"$HIVE_USER\",\"roles\" : [\"read\",\"alert\",\"write\",\"admin\"],\"preferences\" : \"{}\",\"password\" : \"$HIVE_PASSWORD\", \"key\": \"$HIVE_KEY\"}"
   
    # Pre-load custom fields
    #
    # reputation
    curl -v -k "https://$HIVE_IP/thehive/api/list/custom_fields" -H "Authorization: Bearer $HIVE_KEY" -H "Content-Type: application/json" -d "{\"value\":{\"name\": \"reputation\", \"reference\": \"reputation\", \"description\": \"This field provides an overall reputation status for an address/domain.\", \"type\": \"string\", \"options\": []}}"

   
    # Update SOCtopus config with apikey value
    #sed -i "s/hive_key = .*/hive_key = $HIVE_KEY/" $SOCTOPUS_CONFIG

    # Check for correct authentication
    #curl -v -k -H "Authorization: Bearer $HIVE_KEY" "https://$HIVE_IP/thehive/api/user/$USER"

    touch /opt/so/state/thehive.txt

}

if [ -f /opt/so/state/thehive.txt ]; then
    exit 0
else
    rm -f garbage_file
    while ! wget -O garbage_file {{MASTERIP}}:9500 2>/dev/null
    do
      echo "Waiting for Elasticsearch..."
      rm -f garbage_file
      sleep 1
    done
    rm -f garbage_file
    sleep 5
    hive_init
fi
