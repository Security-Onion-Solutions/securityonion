#!/bin/bash
{%- set MASTERIP = salt['pillar.get']('static:masterip', '') %}
{%- set CORTEXUSER = salt['pillar.get']('static:cortexuser', '') %}
{%- set CORTEXPASSWORD = salt['pillar.get']('static:cortexpassword', '') %}
{%- set CORTEXKEY = salt['pillar.get']('static:cortexkey', '') %}

cortex_init(){
    sleep 60
    CORTEX_IP="{{MASTERIP}}"
    CORTEX_USER="{{CORTEXUSER}}"
    CORTEX_PASSWORD="{{CORTEXPASSWORD}}"
    CORTEX_KEY="{{CORTEXKEY}}"    
    SOCTOPUS_CONFIG="/opt/so/saltstack/salt/soctopus/files/SOCtopus.conf"

    # Migrate DB
    curl -v -k -XPOST "https://$CORTEX_IP:/cortex/api/maintenance/migrate"

    # Create intial Cortex user
    curl -v -k "https://$CORTEX_IP/cortex/api/user" -H "Content-Type: application/json" -d "{\"login\" : \"$CORTEX_USER\",\"name\" : \"$CORTEX_USER\",\"roles\" : [\"read\",\"analyze\",\"orgadmin\"],\"preferences\" : \"{}\",\"password\" : \"$CORTEX_PASSWORD\", \"key\": \"$CORTEX_KEY\"}"

    # Enable URLScan.io Analyzer
    curl -v -k -XPOST -H "Authorization: Bearer $CORTEX_KEY" -H "Content-Type: application/json" "https://$CORTEX_IP/cortex/api/organization/analyzer/Urlscan_io_Search_0_1_0" -d '{"name":"Urlscan_io_Search_0_1_0","configuration":{"auto_extract_artifacts":false,"check_tlp":true,"max_tlp":2}}'
    
    # Update SOCtopus config with apikey value
    #sed -i "s/cortex_key = .*/cortex_key = $CORTEX_KEY/" $SOCTOPUS_CONFIG

    touch /opt/so/state/cortex.txt

}

if [ -f /opt/so/state/cortex.txt ]; then
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
    cortex_init
fi
