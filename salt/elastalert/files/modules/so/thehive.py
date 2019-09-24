# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import uuid
import re

from elastalert.alerts import Alerter
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper

class TheHiveAlerter(Alerter):
    """
    Use matched data to create alerts containing observables in an instance of TheHive
    This is a modified version for use with Security Onion
    """

    required_options = set(['hive_connection', 'hive_alert_config'])

    def alert(self, matches):

        connection_details = self.rule['hive_connection']

        api = TheHiveApi(
            connection_details.get('hive_host'),
            connection_details.get('hive_apikey', ''),
            proxies=connection_details.get('hive_proxies', {'http': '', 'https': ''}),
            cert=connection_details.get('hive_verify', False))

        for match in matches:
            context = {'rule': self.rule, 'match': match}

            artifacts = []
            for mapping in self.rule.get('hive_observable_data_mapping', []):
                for observable_type, match_data_key in mapping.items():
                    try:
                        match_data_keys = re.findall(r'\{match\[([^\]]*)\]', match_data_key)
                        rule_data_keys = re.findall(r'\{rule\[([^\]]*)\]', match_data_key)
                        data_keys = match_data_keys + rule_data_keys
                        context_keys = list(context['match'].keys()) + list(context['rule'].keys())
                        if all([True if k in context_keys else False for k in data_keys]):
                            artifacts.append(AlertArtifact(dataType=observable_type, data=match_data_key.format(**context)))
                    except KeyError:
                        raise KeyError('\nformat string\n{}\nmatch data\n{}'.format(match_data_key, context))

            alert_config = {
                'artifacts': artifacts,
                'sourceRef': str(uuid.uuid4())[0:6],
                'title': '{rule[index]}_{rule[name]}'.format(**context)
            }
            alert_config.update(self.rule.get('hive_alert_config', {}))

            for alert_config_field, alert_config_value in alert_config.items():
                if alert_config_field == 'customFields':
                    custom_fields = CustomFieldHelper()
                    for cf_key, cf_value in alert_config_value.items():
                        try:
                            func = getattr(custom_fields, 'add_{}'.format(cf_value['type']))
                        except AttributeError:
                            raise Exception('unsupported custom field type {}'.format(cf_value['type']))
                        value = cf_value['value'].format(**context)
                        func(cf_key, value)
                    alert_config[alert_config_field] = custom_fields.build()
                elif isinstance(alert_config_value, str):
                    alert_config[alert_config_field] = alert_config_value.format(**context)
                elif isinstance(alert_config_value, (list, tuple)):
                    formatted_list = []
                    for element in alert_config_value:
                        try:
                            formatted_list.append(element.format(**context))
                        except (AttributeError, KeyError, IndexError):
                            formatted_list.append(element)
                    alert_config[alert_config_field] = formatted_list

            alert = Alert(**alert_config)
            response = api.create_alert(alert)

            if response.status_code != 201:
                raise Exception('alert not successfully created in TheHive\n{}'.format(response.text))

    def get_info(self):

        return {
            'type': 'hivealerter',
            'hive_host': self.rule.get('hive_connection', {}).get('hive_host', '')
       } 
