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
    curl -v -k "https://$HIVE_IP/thehive/api/user" -H "Content-Type: application/json" -d "{\"login\" : \"$HIVE_USER\",\"name\" : \"$HIVE_USER\",\"roles\" : [\"read\",\"write\",\"admin\"],\"preferences\" : \"{}\",\"password\" : \"$HIVE_PASSWORD\", \"key\": \"$HIVE_KEY\"}"

    # Update SOCtopus config with apikey value
    #sed -i "s/hive_key = .*/hive_key = $HIVE_KEY/" $SOCTOPUS_CONFIG

    # Check for correct authentication
    #curl -v -k -H "Authorization: Bearer $HIVE_KEY" "https://$HIVE_IP/thehive/api/user/$USER"

    touch /opt/so/state/thehive.txt

}

if [ -f /opt/so/state/thehive.txt ]; then
    exit 0
else
    hive_init
fi
