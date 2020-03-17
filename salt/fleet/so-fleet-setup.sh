{% set MAIN_HOSTNAME = salt['grains.get']('host') %}
{% set MAIN_IP = salt['pillar.get']('node:mainip') %}
#!/bin/bash

#so-fleet-setup.sh $FleetEmail

if [ ! "$(docker ps -q -f name=so-fleet)" ]; then
        echo "so-fleet container not running... Exiting..."
        exit 1
fi

initpw=$(date +%s | sha256sum | base64 | head -c 16 ; echo)

docker exec so-fleet /bin/ash -c "echo {{ MAIN_IP }} {{ MAIN_HOSTNAME }} >>  /etc/hosts"
docker exec so-fleet fleetctl config set --address https://{{ MAIN_HOSTNAME }}:443 --tls-skip-verify --url-prefix /fleet
docker exec so-fleet fleetctl setup --email $ --password $initpw

docker exec so-fleet fleetctl apply -f /packs/palantir/Fleet/Endpoints/options.yaml
docker exec so-fleet fleetctl apply -f /packs/palantir/Fleet/Endpoints/MacOS/osquery.yaml
docker exec so-fleet fleetctl apply -f /packs/palantir/Fleet/Endpoints/Windows/osquery.yaml
docker exec so-fleet fleetctl apply -f /packs/hh/hhdefault.yml
docker exec so-fleet /bin/sh -c 'for pack in /packs/palantir/Fleet/Endpoints/packs/*.yaml; do fleetctl apply -f "$pack"; done'


#Generate osquery install packages
#sh so-fleet-packages {{ MAIN_HOSTNAME }}

# Enable Fleet on all the other parts of the infrastructure
#sed -i 's/fleetsetup: 0/fleetsetup: 1/g' /opt/so/saltstack/pillar/static.sls

echo "Installing launcher via salt"
#salt-call state.apply launcher queue=True > /root/launcher.log

echo "Fleet Setup Complete - Login here: https://{{ MAIN_HOSTNAME }}"
echo "Your username is $2 and your password is $initpw"
