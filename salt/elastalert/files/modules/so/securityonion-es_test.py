# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import copy
import importlib.util
import json
import logging
import os
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

# Real ElastAlert when installed (so-elastalert); otherwise stand-ins for what the alerter imports.
try:
    import elastalert.alerts  # noqa: F401
    HAVE_ELASTALERT = True
except ImportError:
    HAVE_ELASTALERT = False

    class Alerter:
        def __init__(self, rule):
            self.rule = rule

    class DateTimeEncoder(json.JSONEncoder):
        def default(self, obj):
            return obj.isoformat() if hasattr(obj, 'isoformat') else json.JSONEncoder.default(self, obj)

    class EAException(Exception):
        pass

    alerts = types.ModuleType('elastalert.alerts')
    alerts.Alerter = Alerter
    alerts.DateTimeEncoder = DateTimeEncoder
    util = types.ModuleType('elastalert.util')
    util.EAException = EAException
    util.elastalert_logger = logging.getLogger('elastalert')
    package = types.ModuleType('elastalert')
    package.alerts = alerts
    package.util = util
    sys.modules.update({'elastalert': package, 'elastalert.alerts': alerts, 'elastalert.util': util})

spec = importlib.util.spec_from_file_location('securityonion_es', os.path.join(os.path.dirname(__file__), 'securityonion-es.py'))
es = importlib.util.module_from_spec(spec)
spec.loader.exec_module(es)

BASE_RULE = {
    'name': 'Many Failed Network Logons To One Host From One Source -- 35a42db6-6629-45af-b8aa-e1fa33c28ef5',
    'detection_title': 'Many Failed Network Logons To One Host From One Source',
    'detection_public_id': '35a42db6-6629-45af-b8aa-e1fa33c28ef5',
    'sigma_level': 'medium',
    'sigma_correlation': 'event_count',
    'event.severity': 3,
    'event.module': 'sigma',
    'event.dataset': 'sigma.alert',
    'es_host': 'manager',
    'es_port': 9200,
    'summary_template': '%count% failed network logons to %host.name% from %source.ip% in %duration%',
}


def correlation_match():
    return {
        'event_count': 3561,
        'window_start': '2026-09-30T18:05:10+00:00',
        '@timestamp': '2026-09-30T18:07:53+00:00',
        'host': {'name': 'sa-delta-02-jb'},
        'source': {'ip': '192.168.198.149'},
        '_id': '6d1c',
        'num_hits': 1,
        'num_matches': 1,
    }


class TestSecurityOnionESAlerter(unittest.TestCase):

    def send(self, rule, match):
        """ Run alert() and return the payload it wrote and the URL it wrote to. """
        alerter = es.SecurityOnionESAlerter(rule)
        response = MagicMock(status_code=201, ok=True)
        with patch.object(es.requests, 'put', return_value=response) as put:
            alerter.alert([match])
        self.assertEqual(put.call_count, 1)
        return json.loads(put.call_args.kwargs['data']), put.call_args.args[0]

    def test_compound_query_key_left_out_of_event_data(self):
        rule = dict(BASE_RULE, compound_query_key=['host.name', 'source.ip'], query_key='host.name,source.ip')
        match = correlation_match()
        match['host.name,source.ip'] = 'sa-delta-02-jb, 192.168.198.149'
        original = copy.deepcopy(match)

        payload, url = self.send(rule, match)

        self.assertNotIn('host.name,source.ip', payload['event_data'])
        self.assertEqual(payload['event_data']['host'], {'name': 'sa-delta-02-jb'})
        self.assertEqual(payload['event_data']['source'], {'ip': '192.168.198.149'})
        self.assertEqual(payload['labels'], {'correlation_group_by': 'host.name, source.ip', 'correlation_group': 'sa-delta-02-jb, 192.168.198.149'})
        self.assertEqual(payload['related'], {'hosts': ['sa-delta-02-jb'], 'ip': ['192.168.198.149']})
        self.assertEqual(payload['event']['kind'], 'alert')
        self.assertEqual(payload['event']['reason'], '3,561 failed network logons to sa-delta-02-jb from 192.168.198.149 in 2 minutes')
        self.assertNotIn('summary', payload['rule'])
        # ElastAlert reuses the match
        self.assertEqual(match, original)
        # id from the group fields, not the compound key
        without_key = {k: v for k, v in match.items() if k != 'host.name,source.ip'}
        self.assertTrue(url.endswith('/' + es.SecurityOnionESAlerter(rule).alert_id(without_key)))

    def test_single_query_key(self):
        rule = dict(BASE_RULE, query_key='user.name', summary_template='%count% failed SOC logins for %user.name%')
        match = {'event_count': 3, 'window_start': '2026-09-30T16:49:52+00:00', '@timestamp': '2026-09-30T16:50:00+00:00',
                 'user': {'name': 'josh@local.invalid'}}

        payload, _ = self.send(rule, match)

        self.assertEqual(payload['labels'], {'correlation_group_by': 'user.name', 'correlation_group': 'josh@local.invalid'})
        self.assertEqual(payload['related'], {'user': ['josh@local.invalid']})
        self.assertEqual(payload['event']['reason'], '3 failed SOC logins for josh@local.invalid')
        self.assertEqual(payload['event_data'], match)

    def test_related_buckets(self):
        rule = dict(BASE_RULE, compound_query_key=['winlog.event_data.TargetUserName', 'source.ip', 'dns.highest_registered_domain'],
                    query_key='winlog.event_data.TargetUserName,source.ip,dns.highest_registered_domain')
        match = correlation_match()
        match.update({'winlog': {'event_data': {'TargetUserName': ['admmig', 'svc', 'admmig']}},
                      'source': {'ip': 'not-an-ip'}, 'dns': {'highest_registered_domain': 'example.com'}})

        payload, _ = self.send(rule, match)

        # deduped; invalid IP skipped; domain stays in the group only
        self.assertEqual(payload['related'], {'user': ['admmig', 'svc']})
        self.assertEqual(payload['labels']['correlation_group'], "['admmig', 'svc', 'admmig'], not-an-ip, example.com")

    def test_group_without_related_fields(self):
        rule = dict(BASE_RULE, query_key='dns.highest_registered_domain')
        match = dict(correlation_match(), dns={'highest_registered_domain': 'example.com'})

        payload, _ = self.send(rule, match)

        self.assertEqual(payload['labels'], {'correlation_group_by': 'dns.highest_registered_domain', 'correlation_group': 'example.com'})
        self.assertNotIn('related', payload)

    def test_plain_rule_has_no_correlation_fields(self):
        match = {'@timestamp': '2026-09-30T16:50:00+00:00', '_id': 'abc', 'process': {'name': 'whoami.exe'}}

        payload, url = self.send(dict(BASE_RULE), match)

        self.assertNotIn('labels', payload)
        self.assertNotIn('related', payload)
        self.assertNotIn('reason', payload['event'])
        self.assertEqual(payload['event']['kind'], 'alert')
        self.assertEqual(payload['event_data'], match)
        self.assertTrue(url.endswith('/' + es.SecurityOnionESAlerter(dict(BASE_RULE)).alert_id(match)))

    def send_responses(self, rule, match, responses):
        """ Run alert() against a sequence of write responses; return the payloads written. """
        alerter = es.SecurityOnionESAlerter(rule)
        with patch.object(es.requests, 'put', side_effect=responses) as put:
            alerter.alert([match])
        return [json.loads(c.kwargs['data']) for c in put.call_args_list]

    def test_rejected_event_data_is_kept_as_text(self):
        rule = dict(BASE_RULE, query_key='user.name', summary_template='%count% failed SOC logins for %user.name%')
        match = {'event_count': 3, 'window_start': '2026-09-30T16:49:52+00:00', '@timestamp': '2026-09-30T16:50:00+00:00',
                 'user': {'name': 'josh@local.invalid'}}
        rejected = MagicMock(status_code=400, ok=False, text='{"error":{"type":"document_parsing_exception"}}')

        first, second = self.send_responses(rule, match, [rejected, MagicMock(status_code=201, ok=True)])

        self.assertIn('event_data', first)
        self.assertNotIn('event_data', second)
        self.assertEqual(json.loads(second['event']['original']), match)
        self.assertEqual(second['tags'], ['alert', 'preserve_original_event'])
        self.assertEqual(first['tags'], ['alert'])
        self.assertTrue(second['error']['message'].startswith('event_data rejected by Elasticsearch: {"error"'))
        self.assertEqual(second['event']['reason'], first['event']['reason'])
        self.assertEqual(second['labels'], first['labels'])
        self.assertEqual(second['related'], first['related'])
        self.assertEqual(second['rule'], first['rule'])

    def test_rejected_twice_is_dropped_without_retry(self):
        rejected = MagicMock(status_code=400, ok=False, text='{"error":{"type":"document_parsing_exception"}}')
        match = {'@timestamp': '2026-09-30T16:50:00+00:00', '_id': 'abc'}

        # no EAException, so no retry
        payloads = self.send_responses(dict(BASE_RULE), match, [rejected, rejected])

        self.assertEqual(len(payloads), 2)

    @unittest.skipUnless(HAVE_ELASTALERT, 'needs ElastAlert, as in the so-elastalert container')
    def test_group_matches_elastalert_silence_key(self):
        from elastalert.elastalert import ElastAlerter
        from elastalert.util import ts_to_dt

        cases = [
            (['host.name', 'source.ip'], {'host': {'name': 'sa-delta-02-jb'}, 'source': {'ip': '192.168.198.149'}}),
            (['winlog.event_data.TargetUserName', 'source.ip'], {'winlog': {'event_data': {'TargetUserName': ['admmig', 'svc']}}, 'source': {'ip': '10.23.23.9'}}),
            (['user.name'], {'user': {'name': "o'brien \"q\" \\ *:?@local.invalid"}}),
        ]
        for keys, fields in cases:
            with self.subTest(keys=keys):
                rule = dict(BASE_RULE, timestamp_field='@timestamp', ts_to_dt=ts_to_dt)
                if len(keys) > 1:
                    rule.update(compound_query_key=keys, query_key=','.join(keys))
                else:
                    rule['query_key'] = keys[0]
                hit = {'_id': 'x', '_source': dict(correlation_match(), **copy.deepcopy(fields))}
                match = ElastAlerter.process_hits(rule, [hit])[0]

                silence_suffix = ElastAlerter.get_named_key_value(None, rule, match, 'query_key')

                self.assertEqual(es.SecurityOnionESAlerter(rule).group(match), silence_suffix)


if __name__ == '__main__':
    unittest.main()
