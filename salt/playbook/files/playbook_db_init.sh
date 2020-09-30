#!/bin/bash
# {%- set MYSQLPASS = salt['pillar.get']('secrets:mysql', None) -%}
# {%- set admin_pass = salt['pillar.get']('secrets:playbook_admin', None) -%}
# {%- set automation_pass = salt['pillar.get']('secrets:playbook_automation', None) %}

default_salt_dir=/opt/so/saltstack/default

# Generate salt + hash for admin user
admin_salt=$(tr -dc "a-zA-Z0-9" < /dev/urandom | fold -w 32 | head -n 1)
admin_stage1_hash=$(echo -n '{{ admin_pass }}' | sha1sum | awk '{print $1}')
admin_hash=$(echo -n "${admin_salt}${admin_stage1_hash}" | sha1sum | awk '{print $1}')
sed -i "s/ADMIN_HASH/${admin_hash}/g" $default_salt_dir/salt/playbook/files/playbook_db_init.sql
sed -i "s/ADMIN_SALT/${admin_salt}/g" $default_salt_dir/salt/playbook/files/playbook_db_init.sql

# Generate salt + hash for automation user
automation_salt=$(tr -dc "a-zA-Z0-9" < /dev/urandom | fold -w 32 | head -n 1)
auto_stage1_hash=$(echo -n '{{ automation_pass }}' | sha1sum | awk '{print $1}')
automation_hash=$(echo -n "${automation_salt}${auto_stage1_hash}" | sha1sum | awk '{print $1}')
sed -i "s/AUTO_HASH/${automation_hash}/g" $default_salt_dir/salt/playbook/files/playbook_db_init.sql
sed -i "s/AUTO_SALT/${automation_salt}/g" $default_salt_dir/salt/playbook/files/playbook_db_init.sql

# Copy file to destination
docker cp $default_salt_dir/salt/playbook/files/playbook_db_init.sql so-mysql:/tmp/playbook_db_init.sql
docker exec so-mysql /bin/bash -c "/usr/bin/mysql -b  -uroot -p{{MYSQLPASS}}  < /tmp/playbook_db_init.sql"