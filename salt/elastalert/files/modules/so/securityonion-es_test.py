# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import copy
from datetime import datetime, timezone
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
except ImportError:

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

        payload, _ = self.send(rule, match)

        self.assertNotIn('host.name,source.ip', payload['event_data'])
        self.assertEqual(payload['event_data']['host'], {'name': 'sa-delta-02-jb'})
        self.assertEqual(payload['event_data']['source'], {'ip': '192.168.198.149'})
        self.assertEqual(payload['labels'], {'correlation_group_by': 'host.name, source.ip', 'correlation_group': 'sa-delta-02-jb, 192.168.198.149'})
        self.assertEqual(payload['related'], {'hosts': ['sa-delta-02-jb'], 'ip': ['192.168.198.149']})
        self.assertEqual(payload['event']['kind'], 'alert')
        self.assertEqual(payload['event']['reason'], '3,561 failed network logons to sa-delta-02-jb from 192.168.198.149 in 2 minutes')
        # ElastAlert reuses the match
        self.assertEqual(match, original)

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

        payload, _ = self.send(dict(BASE_RULE, query_key='dns.highest_registered_domain'), match)

        self.assertNotIn('related', payload)

    def test_plain_rule_has_no_correlation_fields(self):
        # a query_key alone, as from an override, does not make a correlation
        rule = dict(BASE_RULE, query_key='user.name')
        # ElastAlert parses @timestamp for EQL hits
        match = {'@timestamp': datetime(2026, 9, 30, 16, 50, tzinfo=timezone.utc), '_id': 'abc',
                 'process': {'name': 'whoami.exe'}, 'user': {'name': 'josh'}}

        payload, url = self.send(rule, match)

        alerter = es.SecurityOnionESAlerter(rule)
        self.assertNotIn('labels', payload)
        self.assertNotIn('related', payload)
        self.assertNotIn('reason', payload['event'])
        self.assertEqual(payload['event']['kind'], 'alert')
        self.assertEqual(payload['event_data'], dict(match, **{'@timestamp': '2026-09-30T16:50:00+00:00'}))
        self.assertTrue(url.endswith('/' + alerter.alert_id(match)))
        self.assertNotEqual(alerter.alert_id(match), alerter.alert_id(dict(match, _id='abd')))

    def test_ungrouped_correlation_id_ignores_row_hash(self):
        rule = dict(BASE_RULE, summary_template=None)
        first = {k: v for k, v in correlation_match().items() if k not in ('host', 'source')}
        # ES|QL hashes the row into _id, so a later count changes it
        later = dict(first, event_count=3600, _id='9f2a')

        payload, url = self.send(rule, first)

        alerter = es.SecurityOnionESAlerter(rule)
        self.assertEqual(alerter.alert_id(first), alerter.alert_id(later))
        self.assertNotEqual(alerter.alert_id(first), alerter.alert_id(dict(first, **{'@timestamp': '2026-09-30T18:09:00+00:00'})))
        self.assertTrue(url.endswith('/' + alerter.alert_id(first)))
        self.assertEqual(payload['event']['reason'], '3,561 events in 2 minutes')
        self.assertNotIn('labels', payload)

    def test_grouped_correlation_id_unchanged(self):
        """ Ids of alerts already written must not change. """
        rule = dict(BASE_RULE, compound_query_key=['host.name', 'source.ip'], query_key='host.name,source.ip')
        key = f"{BASE_RULE['detection_public_id']}|2026-09-30T18:07:53+00:00|sa-delta-02-jb|192.168.198.149"

        self.assertEqual(es.SecurityOnionESAlerter(rule).alert_id(correlation_match()), es.hashlib.sha256(key.encode()).hexdigest())

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
        # everything else carries over
        self.assertEqual({k: v for k, v in second['event'].items() if k != 'original'}, first['event'])
        changed = ('event_data', 'event', 'error', 'tags')
        self.assertEqual({k: v for k, v in second.items() if k not in changed}, {k: v for k, v in first.items() if k not in changed})

    def test_rejected_twice_is_dropped_without_retry(self):
        rejected = MagicMock(status_code=400, ok=False, text='{"error":{"type":"document_parsing_exception"}}')
        match = {'@timestamp': '2026-09-30T16:50:00+00:00', '_id': 'abc'}

        # no EAException, so no retry
        payloads = self.send_responses(dict(BASE_RULE), match, [rejected, rejected])

        self.assertEqual(len(payloads), 2)


if __name__ == '__main__':
    unittest.main()
