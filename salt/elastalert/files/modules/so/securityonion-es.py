# -*- coding: utf-8 -*-

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.


from time import gmtime, strftime
import requests,json
from elastalert.alerts import Alerter

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityOnionESAlerter(Alerter):
    """
    Use matched data to create alerts in Elasticsearch.
    """

    required_options = set(['detection_title', 'sigma_level'])
    optional_fields = ['sigma_category', 'sigma_product', 'sigma_service']

    def alert(self, matches):
        for match in matches:
            timestamp = strftime("%Y-%m-%d"'T'"%H:%M:%S"'.000Z', gmtime())
            headers = {"Content-Type": "application/json"}

            creds = None
            if 'es_username' in self.rule and 'es_password' in self.rule:
                creds = (self.rule['es_username'], self.rule['es_password'])

            # Start building the rule dict
            rule_info = {
                "name": self.rule['detection_title'],
                "uuid": self.rule['detection_public_id']
            }

            # Add optional fields if they are present in the rule
            for field in self.optional_fields:
                rule_key = field.split('_')[-1]  # Assumes field format "sigma_<key>"
                if field in self.rule:
                    rule_info[rule_key] = self.rule[field]

            # Construct the payload with the conditional rule_info
            payload = {
                "tags": "alert",
                "rule": rule_info,
                "event": {
                    "severity": self.rule['event.severity'],
                    "module": self.rule['event.module'],
                    "dataset": self.rule['event.dataset'],
                    "severity_label": self.rule['sigma_level']
                },
                "sigma_level": self.rule['sigma_level'],
                "event_data": match,
                "@timestamp": timestamp
            }
            url = f"https://{self.rule['es_host']}:{self.rule['es_port']}/logs-detections.alerts-so/_doc/"
            requests.post(url, data=json.dumps(payload), headers=headers, verify=False, auth=creds)

    def get_info(self):
        return {'type': 'SecurityOnionESAlerter'}
