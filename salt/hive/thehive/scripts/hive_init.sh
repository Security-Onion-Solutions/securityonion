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
    HIVE_KEY="{{HIVEKEY}}"
    SOCTOPUS_CONFIG="/opt/so/saltstack/salt/soctopus/files/SOCtopus.conf"

    echo -n "Waiting for TheHive..."
    COUNT=0
    HIVE_CONNECTED="no"
    while [[ "$COUNT" -le 240 ]]; do
        curl --output /dev/null --silent --head --fail -k "https://$HIVE_IP:/thehive"
            if [ $? -eq 0 ]; then
                HIVE_CONNECTED="yes"
                echo "connected!"
                break
            else
                ((COUNT+=1))
                sleep 1
                echo -n "."
            fi
    done
    
    if [ "$HIVE_CONNECTED" == "yes" ]; then
    
        # Migrate DB
        curl -v -k -XPOST "https://$HIVE_IP:/thehive/api/maintenance/migrate"

        # Create intial TheHive user
        curl -v -k "https://$HIVE_IP/thehive/api/user" -H "Content-Type: application/json" -d "{\"login\" : \"$HIVE_USER\",\"name\" : \"$HIVE_USER\",\"roles\" : [\"read\",\"alert\",\"write\",\"admin\"],\"preferences\" : \"{}\",\"password\" : \"$HIVE_PASSWORD\", \"key\": \"$HIVE_KEY\"}"
   
        # Pre-load custom fields
        #
        # reputation
        curl -v -k "https://$HIVE_IP/thehive/api/list/custom_fields" -H "Authorization: Bearer $HIVE_KEY" -H "Content-Type: application/json" -d "{\"value\":{\"name\": \"reputation\", \"reference\": \"reputation\", \"description\": \"This field provides an overall reputation status for an address/domain.\", \"type\": \"string\", \"options\": []}}"

   
        touch /opt/so/state/thehive.txt
    else
        echo "We experienced an issue connecting to TheHive!"
    fi
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
