# -*- coding: utf-8 -*-

from datetime import date   
import requests,json
from elastalert.alerts import Alerter

class PlaybookESAlerter(Alerter):
    """
    Use matched data to create alerts in elasticsearch
    """

    required_options = set(['play_title','play_url','sigma_level','elasticsearch_host'])

    def alert(self, matches):
       for match in matches:
            headers = {"Content-Type": "application/json"}
            payload = {"play_title": self.rule['play_title'],"play_url": self.rule['play_url'],"sigma_level": self.rule['sigma_level'],"data": match}
            today = str(date.today())
            url = f"http://{self.rule['elasticsearch_host']}/playbook-alerts-{today}/_doc/"
            requests.post(url, data=json.dumps(payload), headers=headers, verify=False)
                            
    def get_info(self):
        return {'type': 'PlaybookESAlerter'} 
