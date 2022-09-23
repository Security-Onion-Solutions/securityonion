# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

#!/bin/bash
{% from 'vars/globals.map.jinja' import GLOBALS %}

. /usr/sbin/so-common

docker exec so-kibana grep -q "https://{{ GLOBALS.url_base }}" /usr/share/kibana/x-pack/plugins/osquery/target/public/osquery.chunk.0.js

if [ $? -eq 0 ]
then
  #Do Nothing, pattern has been found
  echo "Pattern found, exiting..."
else
  echo "Pattern not found..."
  docker exec so-kibana sed -i 's|href:h|href:"https://{{ GLOBALS.url_base }}/#/hunt?q=action_id%3A%20"+e+"%20%7C%20groupby%20action_id%20action_data.query%20%7C%20groupby%20host.hostname%20%22metadata.input.beats.host.ip%22"|g' /usr/share/kibana/x-pack/plugins/osquery/target/public/osquery.chunk.0.js
  docker exec so-kibana sed -i 's|View in Discover|View in SO - Hunt|g' /usr/share/kibana/x-pack/plugins/osquery/target/public/osquery.chunk.0.js
  docker restart so-kibana
fi
