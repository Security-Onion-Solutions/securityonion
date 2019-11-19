#so-fleet-setup.sh $MasterIP $FleetEmail

if [ ! "$(docker ps -q -f name=so-fleet)" ]; then
        echo "so-fleet container not running... Exiting..."
        exit 1
fi

initpw=$(date +%s | sha256sum | base64 | head -c 16 ; echo)

docker exec so-fleet fleetctl config set --address https://$1:443 --tls-skip-verify
docker exec so-fleet fleetctl setup --email $2 --password $initpw

docker exec so-fleet fleetctl apply -f /packs/palantir/Fleet/Endpoints/options.yaml
docker exec so-fleet fleetctl apply -f /packs/palantir/Fleet/Endpoints/MacOS/osquery.yaml
docker exec so-fleet fleetctl apply -f /packs/palantir/Fleet/Endpoints/Windows/osquery.yaml
docker exec so-fleet fleetctl apply -f /packs/hh/hhdefault.yml
docker exec so-fleet /bin/sh -c 'for pack in /packs/palantir/Fleet/Endpoints/packs/*.yaml; do fleetctl apply -f "$pack"; done'

esecret=$(sudo docker exec so-fleet fleetctl get enroll-secret)

#Concat fleet.crt & ca.crt  - this is required for launcher connectivity
cat /etc/pki/fleet.crt /etc/pki/ca.crt > /etc/pki/launcher.crt

#Create the output directory
mkdir /opt/so/conf/fleet/packages

#At some point we should version launcher `latest` to avoid hard pinning here
docker run \
  --rm \
  --mount type=bind,source=/opt/so/conf/fleet/packages,target=/output \
  --mount type=bind,source=/etc/pki/launcher.crt,target=/var/launcher/launcher.crt \
  docker.io/soshybridhunter/so-fleet-launcher:HH1.1.0 "$esecret" "$1":8080/fleet

cp /opt/so/conf/fleet/packages/launcher.* /opt/so/saltstack/salt/launcher/packages/
#Update timestamp on packages webpage
sed -i "s@.*Generated.*@Generated: $(date '+%m%d%Y')@g" /opt/so/conf/fleet/packages/index.html
sed -i "s@.*Generated.*@Generated: $(date '+%m%d%Y')@g" /opt/so/saltstack/salt/fleet/osquery-packages.html

# Enable Fleet on all the other parts of the infrastructure
sed -i 's/fleetsetup: 0/fleetsetup: 1/g' /opt/so/saltstack/pillar/static.sls

# Install osquery locally
#if cat /etc/os-release | grep -q 'debian'; then
#   dpkg -i /opt/so/conf/fleet/packages/launcher.deb
#else
#   rpm -i /opt/so/conf/fleet/packages/launcher.rpm
#fi
echo "Installing launcher via salt"
salt-call state.apply launcher queue=True > /root/launcher.log
echo "Fleet Setup Complete - Login here: https://$1"
echo "Your username is $2 and your password is $initpw"
