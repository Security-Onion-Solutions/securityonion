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

esecret=$(sudo docker exec so-fleet fleetctl get enroll-secret)

#Concat fleet.crt & ca.crt  - this is required for launcher connectivity
cat /etc/pki/fleet.crt /etc/pki/ca.crt > /etc/pki/fleet-launcher.crt

#Create the output directory
mkdir /opt/so/conf/fleet/packages

docker run \
  --mount type=bind,source=/opt/so/conf/fleet/packages,target=/output \
  --mount type=bind,source=/etc/pki/fleet-launcher.crt,target=/var/launcher/launcher.crt \
  defensivedepth/hh-launcher "$esecret" "$1":8080

#Update timestamp on packages webpage
sed -i "s@.*Generated.*@Generated: $(date '+%m%d%Y')@g" /opt/so/conf/fleet/packages/index.html

echo "Fleet Setup Complete - Login here: https://$1"
echo "Your username is $2 and your password is $initpw"
