# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.
#
# Note: Per the Elastic License 2.0, the second limitation states:
#
#   "You may not move, change, disable, or circumvent the license key functionality
#    in the software, and you may not remove or obscure any functionality in the
#    software that is protected by the license key."

{% from 'kafka/map.jinja' import KAFKAMERGED %}
{% from 'vars/globals.map.jinja' import GLOBALS %}

include:
{# Run kafka/nodes.sls before Kafka is enabled, so kafka nodes pillar is setup #}
{% if grains.role in ['so-manager','so-managersearch', 'so-standalone'] %}
  - kafka.nodes
{% endif %}
{% if GLOBALS.pipeline == "KAFKA" and KAFKAMERGED.enabled %}
{%   if grains.role in ['so-manager', 'so-managersearch', 'so-standalone', 'so-receiver'] %}
  - kafka.enabled
{# Searchnodes only run kafka.ssl state when Kafka is enabled #}
{%   elif grains.role == "so-searchnode" %}
  - kafka.ssl
{%   endif %}
{% else %}
  - kafka.disabled
{% endif %}
