#!/bin/bash
# {%- set MYSQLPASS = salt['pillar.get']('secrets:mysql', None) -%}
# {%- set admin_pass = salt['pillar.get']('secrets:playbook_admin', None) -%}
# {%- set automation_pass = salt['pillar.get']('secrets:playbook_automation', None) %}

default_salt_dir=/opt/so/saltstack/default
local_salt_dir=/opt/so/saltstack/local

# Generate salt + hash for admin user
admin_salt=$(tr -dc "a-zA-Z0-9" < /dev/urandom | fold -w 32 | head -n 1)
admin_stage1_hash=$(echo -n '{{ admin_pass }}' | sha1sum | awk '{print $1}')
admin_hash=$(echo -n "${admin_salt}${admin_stage1_hash}" | sha1sum | awk '{print $1}')
sed -i "s/ADMIN_HASH/${admin_hash}/g" $default_salt_dir/salt/playbook/files/playbook_db_init.sql
sed -i "s/ADMIN_SALT/${admin_salt}/g" $default_salt_dir/salt/playbook/files/playbook_db_init.sql

# Copy file to destination + execute SQL
docker cp $default_salt_dir/salt/playbook/files/playbook_db_init.sql so-mysql:/tmp/playbook_db_init.sql
docker exec so-mysql /bin/bash -c "/usr/bin/mysql -b  -uroot -p{{MYSQLPASS}}  < /tmp/playbook_db_init.sql"

#Create Automation user
automation_group=6

mapfile -t automation_res < <(
    curl -s --location --request POST 'http://127.0.0.1:3200/playbook/users.json' --user "admin:{{ admin_pass }}" --header 'Content-Type: application/json' --data '{
        "user" : {
            "login" : "Automation",
            "password": "{{ automation_pass }}",
            "firstname": "SecOps",
            "lastname": "Automation",
            "mail": "automation2@localhost.local"
        }
    }' | jq -r '.user.api_key, .user.id'
)

automation_api_key=${automation_res[0]}
automation_user_id=${automation_res[1]}

curl --location --request POST "http://127.0.0.1:3200/playbook/groups/${automation_group}/users.json" \
    --user "admin:{{ admin_pass }}" \
    --header 'Content-Type: application/json' \
    --data "{
        \"user_id\" : ${automation_user_id}
    }"

if (grep -qi "playbook_api_key" $local_salt_dir/pillar/global.sls); then
    sed -i "/s/playbook_api_key:.*/playbook_api_key: ${automation_api_key}/g" $local_salt_dir/pillar/global.sls
else
    echo "  playbook_api_key: ${automation_api_key}" >> $local_salt_dir/pillar/global.sls
fi