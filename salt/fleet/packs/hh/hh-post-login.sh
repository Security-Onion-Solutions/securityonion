#!/bin/sh
echo "Applying Post Configuration for Osquery"
fleetctl apply -f /packs/hh/osquery.conf
fleetctl apply -f /packs/hh/hhdefault/yml
fleetctl apply -f /packs/palantir/Fleet/Endpoints/options.yaml
fleetctl apply -f /packs/palantir/Fleet/Endpoints/MacOS/osquery.yaml
fleetctl apply -f /packs/palantir/Fleet/Endpoints/Windows/osquery.yaml
for pack in /packs/palantir/Fleet/Endpoints/packs/*.yaml;
 do fleetctl apply -f "$pack"
done
echo ""
echo "You can now exit the container by typing exit"
