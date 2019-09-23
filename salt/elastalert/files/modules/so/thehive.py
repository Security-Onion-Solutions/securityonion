# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import uuid

from elastalert.alerts import Alerter
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper


class TheHiveAlerter(Alerter):
    """
    Use matched data to create alerts containing observables in an instance of TheHive
    """

    required_options = set(['hive_connection', 'hive_alert_config'])

    def get_aggregation_summary_text(self, matches):
        text = super(HiveAlerter, self).get_aggregation_summary_text(matches)
        if text:
            text = u'```\n{0}```\n'.format(text)
        return text

    def create_artifacts(self, match):
        artifacts = []
        context = {'rule': self.rule, 'match': match}
        for mapping in self.rule.get('hive_observable_data_mapping', []):
            for observable_type, match_data_key in mapping.iteritems():
                try:
                    artifacts.append(AlertArtifact(dataType=observable_type, data=match_data_key.format(**context)))
                except KeyError as e:
                    print('format string {} fail cause no key {} in {}'.format(e, match_data_key, context))
        return artifacts

    def create_alert_config(self, match):
        context = {'rule': self.rule, 'match': match}
        alert_config = {
            'artifacts': self.create_artifacts(match),
            'sourceRef': str(uuid.uuid4())[0:6],
            'title': '{rule[name]}'.format(**context)
        }

        alert_config.update(self.rule.get('hive_alert_config', {}))

        for alert_config_field, alert_config_value in alert_config.iteritems():
            if alert_config_field == 'customFields':
                custom_fields = CustomFieldHelper()
                for cf_key, cf_value in alert_config_value.iteritems():
                    try:
                        func = getattr(custom_fields, 'add_{}'.format(cf_value['type']))
                    except AttributeError:
                        raise Exception('unsupported custom field type {}'.format(cf_value['type']))
                    value = cf_value['value'].format(**context)
                    func(cf_key, value)
                alert_config[alert_config_field] = custom_fields.build()
            elif isinstance(alert_config_value, basestring):
                alert_config[alert_config_field] = alert_config_value.format(**context)
            elif isinstance(alert_config_value, (list, tuple)):
                formatted_list = []
                for element in alert_config_value:
                    try:
                        formatted_list.append(element.format(**context))
                    except (AttributeError, KeyError, IndexError):
                        formatted_list.append(element.format(**context))
                    except (AttributeError, KeyError, IndexError):
                        formatted_list.append(element)
                alert_config[alert_config_field] = formatted_list

        return alert_config

    def send_to_thehive(self, alert_config):
        connection_details = self.rule['hive_connection']
        api = TheHiveApi(
            connection_details.get('hive_host', ''),
            connection_details.get('hive_apikey', ''),
            proxies=connection_details.get('hive_proxies', {'http': '', 'https': ''}),
            cert=connection_details.get('hive_verify', False))

        alert = Alert(**alert_config)
        response = api.create_alert(alert)

        if response.status_code != 201:
            raise Exception('alert not successfully created in TheHive\n{}'.format(response.text))

    def alert(self, matches):
        if self.rule.get('hive_alert_config_type', 'custom') != 'classic':
            for match in matches:
                alert_config = self.create_alert_config(match)
                self.send_to_thehive(alert_config)
        else:
            alert_config = self.create_alert_config(matches[0])
            artifacts = []
            for match in matches:
                artifacts += self.create_artifacts(match)
                if 'related_events' in match:
                    for related_event in match['related_events']:
                        artifacts += self.create_artifacts(related_event)

            alert_config['artifacts'] = artifacts
            alert_config['title'] = self.create_title(matches)
            alert_config['description'] = self.create_alert_body(matches)
            self.send_to_thehive(alert_config)

    def get_info(self):

        return {
            'type': 'hivealerter',
            'hive_host': self.rule.get('hive_connection', {}).get('hive_host', '')
        }
