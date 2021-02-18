#!/bin/bash
# {%- set admin_pass = salt['pillar.get']('secrets:playbook_admin', None) -%}
# {%- set automation_pass = salt['pillar.get']('secrets:playbook_automation', None) %}

set -e

local_salt_dir=/opt/so/saltstack/local

try_count=6
interval=10

while [[ $try_count -le 6 ]]; do
    if docker top "so-playbook" &>/dev/null; then
        automation_group=6

        # Create user and retrieve api_key and user_id from response
        mapfile -t automation_res < <(
            curl -s --location --request POST 'http://127.0.0.1:3200/playbook/users.json' --user "admin:{{ admin_pass }}" --header 'Content-Type: application/json' --data '{
                "user" : {
                    "login" : "automation",
                    "password": "{{ automation_pass }}",
                    "firstname": "SecOps",
                    "lastname": "Automation",
                    "mail": "automation2@localhost.local"
                }
            }' | jq -r '.user.api_key, .user.id'
        )

        automation_api_key=${automation_res[0]}
        automation_user_id=${automation_res[1]}

        # Add user_id from newly created user to Automation group
        curl -s --location --request POST "http://127.0.0.1:3200/playbook/groups/${automation_group}/users.json" \
            --user "admin:{{ admin_pass }}" \
            --header 'Content-Type: application/json' \
            --data "{
                \"user_id\" : ${automation_user_id}
            }"

        # Search for the needed keys in the global pillar file, if missing then add them
        if (grep -Pzq 'playbook:\n  api_key:.*' $local_salt_dir/pillar/global.sls); then
            sed -e '1h;2,$H;$!d;g' -e "s/playbook:\n  api_key:.*/playbook:\n  api_key: ${automation_api_key}/m" -i $local_salt_dir/pillar/global.sls
        else
            {
                echo "playbook:"
                echo "  api_key: ${automation_api_key}" 
            } >> $local_salt_dir/pillar/global.sls
        fi
        exit 0
    fi
    ((try_count++))
    sleep "${interval}s"
done

# Timeout exceeded, exit with non-zero exit code
exit 1
