# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

{% from 'strelka/map.jinja' import STRELKAMERGED %}

include:
{% if STRELKAMERGED.coordinator.enabled %}
  - strelka.coordinator.enabled
{% else %}
  - strelka.coordinator.disabled
{% endif %}

{% if STRELKAMERGED.gatekeeper.enabled %}
  - strelka.gatekeeper.enabled
{% else %}
  - strelka.gatekeeper.disabled
{% endif %}

{% if STRELKAMERGED.frontend.enabled %}
  - strelka.frontend.enabled
{% else %}
  - strelka.frontend.disabled
{% endif %}

{% if STRELKAMERGED.backend.enabled %}
  - strelka.backend.enabled
{% else %}
  - strelka.backend.disabled
{% endif %}

{% if STRELKAMERGED.manager.enabled %}
  - strelka.manager.enabled
{% else %}
  - strelka.manager.disabled
{% endif %}

{% if STRELKAMERGED.filestream.enabled %}
  - strelka.filestream.enabled
{% else %}
  - strelka.filestream.disabled
{% endif %}
