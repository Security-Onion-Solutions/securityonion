# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
import unittest
from unittest.mock import MagicMock

from elasticsearch.exceptions import ConflictError, ConnectionError, RequestError

spec = importlib.util.spec_from_file_location('securityonion_es', os.path.join(os.path.dirname(__file__), 'securityonion-es.py'))
es = importlib.util.module_from_spec(spec)
spec.loader.exec_module(es)

BASE_RULE = {
    'detection_title': 'Many Failed Network Logons To One Host From One Source',
    'detection_public_id': '35a42db6-6629-45af-b8aa-e1fa33c28ef5',
    'sigma_level': 'medium',
    'sigma_correlation': 'event_count',
    'event.severity': 3,
    'event.module': 'sigma',
    'event.dataset': 'sigma.alert',
    'summary_template': '%count% failed network logons to %host.name% from %source.ip% in %duration%',
}

PLAIN_RULE = {k: v for k, v in BASE_RULE.items() if k not in ('sigma_correlation', 'summary_template')}


def correlation_match():
    return {
        'event_count': 3561,
        'window_start': '2026-09-30T18:05:10+00:00',
        '@timestamp': '2026-09-30T18:07:53+00:00',
        'host': {'name': 'host-01'},
        'source': {'ip': '192.0.2.10'},
        '_id': '6d1c',
        'num_hits': 1,
        'num_matches': 1,
    }


class TestSecurityOnionESAlerter(unittest.TestCase):

    def creates(self, rule, match, effects=None):
        """Run alert(); return (body, id) of each create."""
        alerter = es.SecurityOnionESAlerter(rule)
        alerter.es = MagicMock()
        alerter.es.create.side_effect = effects
        alerter.alert([match])
        calls = alerter.es.create.call_args_list
        self.assertTrue(all(c.kwargs['index'] == 'logs-detections.alerts-so' for c in calls))
        return [(json.loads(json.dumps(c.kwargs['body'], cls=es.DateTimeEncoder)), c.kwargs['id']) for c in calls]

    def send(self, rule, match):
        """Run alert(); return the payload it wrote and its id."""
        (payload, alert_id), = self.creates(rule, match)
        return payload, alert_id

    def test_compound_query_key_left_out_of_event_data(self):
        rule = dict(BASE_RULE, compound_query_key=['host.name', 'source.ip'], query_key='host.name,source.ip')
        match = correlation_match()
        match['host.name,source.ip'] = 'host-01, 192.0.2.10'
        original = copy.deepcopy(match)

        payload, _ = self.send(rule, match)

        self.assertNotIn('host.name,source.ip', payload['event_data'])
        self.assertEqual(payload['event_data']['host'], {'name': 'host-01'})
        self.assertEqual(payload['event_data']['source'], {'ip': '192.0.2.10'})
        self.assertEqual(payload['rule'], {'name': BASE_RULE['detection_title'], 'uuid': BASE_RULE['detection_public_id'], 'correlation': 'event_count'})
        self.assertEqual(payload['labels'], {'correlation_group_by': 'host.name, source.ip', 'correlation_group': 'host-01, 192.0.2.10'})
        self.assertEqual(payload['related'], {'hosts': ['host-01'], 'ip': ['192.0.2.10']})
        self.assertEqual(payload['event']['kind'], 'alert')
        self.assertEqual(payload['event']['reason'], '3,561 failed network logons to host-01 from 192.0.2.10 in 2 minutes')
        # ElastAlert reuses the match
        self.assertEqual(match, original)

    def test_single_query_key(self):
        rule = dict(BASE_RULE, query_key='user.name', summary_template='%count% failed SOC logins for %user.name%')
        match = {'event_count': 3, 'window_start': '2026-09-30T16:49:52+00:00', '@timestamp': '2026-09-30T16:50:00+00:00',
                 'user': {'name': 'user@example.invalid'}}

        payload, _ = self.send(rule, match)

        self.assertEqual(payload['labels'], {'correlation_group_by': 'user.name', 'correlation_group': 'user@example.invalid'})
        self.assertEqual(payload['related'], {'user': ['user@example.invalid']})
        self.assertEqual(payload['event']['reason'], '3 failed SOC logins for user@example.invalid')
        self.assertEqual(payload['event_data'], match)

    def test_related_buckets(self):
        rule = dict(BASE_RULE, compound_query_key=['winlog.event_data.TargetUserName', 'source.ip', 'dns.highest_registered_domain'],
                    query_key='winlog.event_data.TargetUserName,source.ip,dns.highest_registered_domain')
        match = correlation_match()
        match.update({'winlog': {'event_data': {'TargetUserName': ['admin1', 'svc', 'admin1']}},
                      'source': {'ip': 'not-an-ip'}, 'dns': {'highest_registered_domain': 'example.com'}})

        payload, _ = self.send(rule, match)

        # deduped; invalid IP skipped; domain stays in the group only
        self.assertEqual(payload['related'], {'user': ['admin1', 'svc']})
        self.assertEqual(payload['labels']['correlation_group'], "['admin1', 'svc', 'admin1'], not-an-ip, example.com")

        payload, _ = self.send(dict(BASE_RULE, query_key='dns.highest_registered_domain'), match)

        self.assertNotIn('related', payload)

    def test_related_uses_original_spellings(self):
        rule = dict(BASE_RULE, query_key='user.name', summary_template=None)
        match = {'event_count': 3, 'window_start': '2026-09-30T16:49:52+00:00', '@timestamp': '2026-09-30T16:50:00+00:00',
                 'user': {'name': 'admin', 'name_spellings': ['Admin', 'admin', 'ADMIN']}}

        payload, _ = self.send(rule, match)

        # the group shows the lowercased value; related.user finds every spelling
        self.assertEqual(payload['labels']['correlation_group'], 'admin')
        self.assertEqual(payload['related'], {'user': ['Admin', 'admin', 'ADMIN']})
        self.assertEqual(payload['event']['reason'], '3 events for user.name admin in 8 seconds')

    def test_plain_rule_has_no_correlation_fields(self):
        # a query_key alone (e.g. from an override) isn't a correlation
        rule = dict(PLAIN_RULE, query_key='user.name')
        # ElastAlert parses @timestamp for EQL hits
        match = {'@timestamp': datetime(2026, 9, 30, 16, 50, tzinfo=timezone.utc), '_id': 'abc',
                 'process': {'name': 'whoami.exe'}, 'user': {'name': 'user'}}

        payload, alert_id = self.send(rule, match)

        alerter = es.SecurityOnionESAlerter(rule)
        self.assertEqual(payload['rule'], {'name': PLAIN_RULE['detection_title'], 'uuid': PLAIN_RULE['detection_public_id']})
        self.assertNotIn('labels', payload)
        self.assertNotIn('related', payload)
        self.assertNotIn('reason', payload['event'])
        self.assertEqual(payload['event']['kind'], 'alert')
        self.assertEqual(payload['event_data'], dict(match, **{'@timestamp': '2026-09-30T16:50:00+00:00'}))
        self.assertEqual(alert_id, alerter.alert_id(match))
        self.assertNotEqual(alerter.alert_id(match), alerter.alert_id(dict(match, _id='abd')))
        self.assertNotEqual(alerter.alert_id(match), es.SecurityOnionESAlerter(dict(rule, detection_public_id='other')).alert_id(match))
        # without an _id, never deduplicated
        self.assertNotEqual(alerter.alert_id({'_id': None}), alerter.alert_id({'_id': None}))

    def test_ungrouped_correlation_id_ignores_row_hash(self):
        rule = dict(BASE_RULE, summary_template=None)
        first = {k: v for k, v in correlation_match().items() if k not in ('host', 'source')}
        # ES|QL hashes the row into _id, so a later count changes it
        later = dict(first, event_count=3600, _id='9f2a')

        payload, alert_id = self.send(rule, first)

        alerter = es.SecurityOnionESAlerter(rule)
        self.assertEqual(alerter.alert_id(first), alerter.alert_id(later))
        self.assertNotEqual(alerter.alert_id(first), alerter.alert_id(dict(first, **{'@timestamp': '2026-09-30T18:09:00+00:00'})))
        self.assertEqual(alert_id, alerter.alert_id(first))
        self.assertEqual(payload['event']['reason'], '3,561 events in 2 minutes')
        self.assertNotIn('labels', payload)

    def test_temporal_count_column(self):
        rule = dict(BASE_RULE, sigma_correlation='temporal', summary_template=None)
        match = {'event_type_count': 2, 'window_start': '2026-09-30T16:49:52+00:00', '@timestamp': '2026-09-30T16:50:00+00:00'}

        payload, _ = self.send(rule, match)

        self.assertEqual(payload['event']['reason'], '2 correlated rules matched in 8 seconds')

    def test_grouped_correlation_id_unchanged(self):
        """Ids of alerts already written must not change."""
        rule = dict(BASE_RULE, compound_query_key=['host.name', 'source.ip'], query_key='host.name,source.ip')
        key = f"{BASE_RULE['detection_public_id']}|2026-09-30T18:07:53+00:00|host-01|192.0.2.10"

        self.assertEqual(es.SecurityOnionESAlerter(rule).alert_id(correlation_match()), es.hashlib.sha256(key.encode()).hexdigest())

    def test_rejected_event_data_is_kept_as_text(self):
        rule = dict(BASE_RULE, query_key='user.name', summary_template='%count% failed SOC logins for %user.name%')
        match = {'event_count': 3, 'window_start': '2026-09-30T16:49:52+00:00', '@timestamp': '2026-09-30T16:50:00+00:00',
                 'user': {'name': 'user@example.invalid'}}
        rejected = RequestError(400, 'document_parsing_exception', {})

        (first, _), (second, _) = self.creates(rule, match, [rejected, None])

        self.assertIn('event_data', first)
        self.assertNotIn('event_data', second)
        self.assertEqual(json.loads(second['event']['original']), match)
        self.assertEqual(second['tags'], ['alert', 'preserve_original_event'])
        self.assertEqual(first['tags'], ['alert'])
        self.assertTrue(second['error']['message'].startswith('event_data rejected by Elasticsearch: '))
        self.assertIn('document_parsing_exception', second['error']['message'])
        # everything else carries over
        self.assertEqual({k: v for k, v in second['event'].items() if k != 'original'}, first['event'])
        changed = ('event_data', 'event', 'error', 'tags')
        self.assertEqual({k: v for k, v in second.items() if k not in changed}, {k: v for k, v in first.items() if k not in changed})

    def test_rejected_dates_are_kept_as_text(self):
        match = {'@timestamp': datetime(2026, 9, 30, 16, 50, tzinfo=timezone.utc), '_id': 'abc'}

        _, (second, _) = self.creates(PLAIN_RULE, match, [RequestError(400, 'document_parsing_exception', {}), None])

        self.assertEqual(json.loads(second['event']['original']), {'@timestamp': '2026-09-30T16:50:00+00:00', '_id': 'abc'})

    def test_rejected_twice_is_dropped_without_retry(self):
        rejected = RequestError(400, 'document_parsing_exception', {})
        match = {'@timestamp': '2026-09-30T16:50:00+00:00', '_id': 'abc'}

        with self.assertLogs('elastalert', 'ERROR') as logs:
            self.assertEqual(len(self.creates(PLAIN_RULE, match, [rejected, rejected])), 2)

        self.assertIn('Dropping alert', logs.output[0])

    def test_write_failure_is_retried(self):
        match = {'@timestamp': '2026-09-30T16:50:00+00:00', '_id': 'abc'}

        with self.assertRaisesRegex(es.EAException, 'Unable to write the alert to Elasticsearch'):
            self.creates(PLAIN_RULE, match, [ConnectionError('N/A', 'refused', None)])

    def test_repeat_id_is_ignored(self):
        match = {'@timestamp': '2026-09-30T16:50:00+00:00', '_id': 'abc'}

        self.assertEqual(len(self.creates(PLAIN_RULE, match, [ConflictError(409, 'version_conflict_engine_exception', {})])), 1)

    def test_correlation_fields_are_optional(self):
        rule = dict(BASE_RULE, query_key='source.ip')
        # no window_start: the summary cannot be built
        match = {k: v for k, v in correlation_match().items() if k != 'window_start'}

        with self.assertLogs('elastalert', 'WARNING') as logs:
            payload, _ = self.send(rule, match)

        self.assertIn('without its correlation summary', logs.output[0])
        self.assertEqual(payload['event']['kind'], 'alert')
        self.assertNotIn('reason', payload['event'])
        self.assertNotIn('labels', payload)
        self.assertNotIn('related', payload)

    def test_unstable_id_still_writes(self):
        # no @timestamp: the window end is unknown
        match = {k: v for k, v in correlation_match().items() if k not in ('@timestamp', 'window_start')}

        with self.assertLogs('elastalert', 'WARNING') as logs:
            payload, alert_id = self.send(BASE_RULE, match)

        self.assertIn('without a stable id', logs.output[0])
        self.assertEqual(len(alert_id), 32)
        self.assertEqual(payload['event_data'], match)

    def test_summary_formats_values(self):
        rule = dict(BASE_RULE, sigma_correlation='value_avg', query_key='source.ip',
                    summary_template='%count% for %source.ip% to %destination.port% %no.such.field%')
        match = {'value_avg': 2.5, 'window_start': '2026-09-30T16:49:52+00:00', '@timestamp': '2026-09-30T16:50:00+00:00',
                 'source': {'ip': '192.0.2.10'}, 'destination': {'port': [22, 80, 443, 8080, 8443]}}

        payload, _ = self.send(rule, match)

        self.assertEqual(payload['event']['reason'], '2.50 for 192.0.2.10 to 22, 80, 443 and 2 more %no.such.field%')
        self.assertEqual(es.SecurityOnionESAlerter.format_count('n/a'), 'n/a')

    def test_get_info(self):
        self.assertEqual(es.SecurityOnionESAlerter(PLAIN_RULE).get_info(), {'type': 'SecurityOnionESAlerter'})
