# -*- coding: utf-8 -*-

from time import gmtime, strftime
import requests,json
from elastalert.alerts import Alerter

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class PlaybookESAlerter(Alerter):
    """
    Use matched data to create alerts in elasticsearch
    """

    required_options = set(['play_title','play_url','sigma_level','elasticsearch_host'])

    def alert(self, matches):
       for match in matches:
            today = strftime("%Y.%m.%d", gmtime())
            timestamp = strftime("%Y-%m-%d"'T'"%H:%M:%S", gmtime())
            headers = {"Content-Type": "application/json"}
            payload = {"rule": { "name": self.rule['play_title'],"case_template": self.rule['play_id'],"uuid": self.rule['play_id'],"category": self.rule['rule.category']},"event":{ "severity": self.rule['event.severity'],"module": self.rule['event.module'],"dataset": self.rule['event.dataset'],"severity_label": self.rule['sigma_level']},"kibana_pivot": self.rule['kibana_pivot'],"soc_pivot": self.rule['soc_pivot'],"play_url": self.rule['play_url'],"sigma_level": self.rule['sigma_level'],"event_data": match, "@timestamp": timestamp}
            url = f"https://{self.rule['elasticsearch_host']}/so-playbook-alerts-{today}/_doc/"
            requests.post(url, data=json.dumps(payload), headers=headers, verify=False)
                            
    def get_info(self):
        return {'type': 'PlaybookESAlerter'} 