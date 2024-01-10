#!/bin/bash
# {%- set admin_pass = salt['pillar.get']('secrets:playbook_admin', None) -%}
# {%- set automation_pass = salt['pillar.get']('secrets:playbook_automation', None) %}

local_salt_dir=/opt/so/saltstack/local

try_count=6
interval=10

while [[ $try_count -le 6 ]]; do
    if docker top "so-playbook" &>/dev/null; then
        automation_group=6

        # Create user and retrieve api_key and user_id from response
        mapfile -t automation_res < <(
            curl -s --location --request POST 'http://127.0.0.1:3000/playbook/users.json' --user "admin:{{ admin_pass }}" --header 'Content-Type: application/json' --data '{
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
        curl -s --location --request POST "http://127.0.0.1:3000/playbook/groups/${automation_group}/users.json" \
            --user "admin:{{ admin_pass }}" \
            --header 'Content-Type: application/json' \
            --data "{
                \"user_id\" : ${automation_user_id}
            }"

        # Update the Automation API key in the secrets pillar
        so-yaml.py remove $local_salt_dir/pillar/secrets.sls secrets.playbook_automation_api_key
        printf '%s\n'\
            "  playbook_automation_api_key: $automation_api_key" >> $local_salt_dir/pillar/secrets.sls
        exit 0
    fi
    ((try_count++))
    sleep "${interval}s"
done

# Timeout exceeded, exit with non-zero exit code
exit 1
