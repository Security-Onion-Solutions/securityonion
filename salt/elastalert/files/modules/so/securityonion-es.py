# -*- coding: utf-8 -*-

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
import uuid

import urllib3
from elasticsearch.exceptions import ConflictError, ElasticsearchException, RequestError
from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger, elasticsearch_client, lookup_es_key, ts_to_dt

# grid runs verify_certs: false; also quiets ElastAlert's own queries
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALERT_INDEX = 'logs-detections.alerts-so'
# ES error text kept in logs and alerts
ERROR_TEXT_LIMIT = 500
# a match missing backend columns (window_start, count, @timestamp); the alert is still written
MATCH_ERRORS = (KeyError, TypeError, ValueError)


class SecurityOnionESAlerter(Alerter):
    """
    Use matched data to create alerts in Elasticsearch.
    """

    required_options = {'detection_title', 'sigma_level'}
    optional_fields = ['sigma_category', 'sigma_product', 'sigma_service', 'sigma_correlation']

    # count column and default summary per type; stored alert data, so not localized
    CORRELATION_COUNTS = {
        'event_count': ('event_count', '%count% events'),
        'value_count': ('value_count', '%count% distinct values'),
        'temporal': ('event_type_count', '%count% correlated rules matched'),
        'value_sum': ('value_sum', 'total %count%'),
        'value_avg': ('value_avg', 'average %count%'),
        'value_percentile': ('value_percentile', 'percentile %count%'),
        'value_median': ('value_median', 'median %count%'),
    }
    PLACEHOLDER = re.compile(r'%([^%\s]+)%')
    # group-by fields copied into ECS related.*
    RELATED_USERS = {'user.name', 'winlog.event_data.TargetUserName', 'winlog.event_data.SubjectUserName'}
    RELATED_HOSTS = {'host.name', 'host.hostname', 'winlog.computer_name'}

    def __init__(self, rule):
        super().__init__(rule)
        # uses the grid's TLS, auth and timeout settings
        self.es = elasticsearch_client(rule)

    @property
    def is_correlation(self):
        return bool(self.rule.get('sigma_correlation'))

    def query_keys(self):
        """compound_query_key holds the list; query_key is flattened to a string."""
        if self.rule.get('compound_query_key'):
            return self.rule['compound_query_key']
        if self.rule.get('query_key'):
            return [self.rule['query_key']]
        return []

    def alert_id(self, match):
        """Stable id: window end + group values for correlations, source _id otherwise; random without one."""
        if self.is_correlation:
            # ungrouped rows have a hashed _id that changes with the count
            values = ''.join(f"|{lookup_es_key(match, k)}" for k in self.query_keys())
            key = f"{self.rule['detection_public_id']}|{ts_to_dt(match['@timestamp']).isoformat()}{values}"
        elif match.get('_id'):
            key = f"{self.rule['detection_public_id']}|{match['_id']}"
        else:
            return uuid.uuid4().hex

        return hashlib.sha256(key.encode('utf-8')).hexdigest()

    def group(self, match):
        """Group-by values, joined like ElastAlert's realert key."""
        return ', '.join(str(lookup_es_key(match, k)) for k in self.query_keys())

    def related_bucket(self, key):
        if key == 'ip' or key.endswith('.ip'):
            return 'ip'
        if key in self.RELATED_USERS or key.endswith('.user.name'):
            return 'user'
        if key in self.RELATED_HOSTS:
            return 'hosts'
        return None

    @staticmethod
    def valid_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def related(self, match):
        """ECS related.* from group-by values; skips invalid IPs."""
        related = {}
        for key in self.query_keys():
            bucket = self.related_bucket(key)
            if not bucket:
                continue
            # original spellings of a lowercased group
            value = lookup_es_key(match, f"{key}_spellings")
            if value is None:
                value = lookup_es_key(match, key)
            for v in value if isinstance(value, list) else [value]:
                if v is None or (bucket == 'ip' and not self.valid_ip(str(v))):
                    continue
                # dict: ordered and deduped
                related.setdefault(bucket, {})[str(v)] = None
        return {bucket: list(values) for bucket, values in related.items()}

    def event_data(self, match):
        """The match minus the compound query_key field, which ES would map by its last part."""
        if not self.rule.get('compound_query_key'):
            return match
        return {k: v for k, v in match.items() if k != self.rule['query_key']}

    @staticmethod
    def format_value(value):
        if isinstance(value, list):
            shown = ', '.join(str(v) for v in value[:3])
            return shown if len(value) <= 3 else f"{shown} and {len(value) - 3} more"
        return str(value)

    @staticmethod
    def format_count(value):
        if isinstance(value, float) and not value.is_integer():
            return f"{value:,.2f}"
        if isinstance(value, (int, float)):
            return f"{int(value):,}"
        return str(value)

    @staticmethod
    def format_duration(seconds):
        for unit, size in (('hour', 3600), ('minute', 60)):
            if seconds >= 2 * size:
                return f"{seconds // size} {unit}s"
        return f"{seconds} second{'' if seconds == 1 else 's'}"

    def summary(self, match):
        """One-line correlation summary."""
        column, label = self.CORRELATION_COUNTS.get(self.rule['sigma_correlation'], (None, '%count%'))
        start = ts_to_dt(match['window_start'])
        end = ts_to_dt(match['@timestamp'])
        values = {
            'count': self.format_count(match.get(column)),
            'start': start.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'end': end.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'duration': self.format_duration(int((end - start).total_seconds())),
        }

        template = self.rule.get('summary_template')
        if not template:
            groups = ', '.join(f"{k} %{k}%" for k in self.query_keys())
            template = f"{label} for {groups} in %duration%" if groups else f"{label} in %duration%"

        def fill(m):
            if m[1] in values:
                return values[m[1]]
            value = lookup_es_key(match, m[1])
            # unknown placeholders stay visible so typos show
            return m[0] if value is None else self.format_value(value)

        return self.PLACEHOLDER.sub(fill, template)

    def alert(self, matches):
        for match in matches:
            try:
                alert_id = self.alert_id(match)
            except MATCH_ERRORS as e:
                elastalert_logger.warning("Writing alert for rule %s without a stable id, so a retry may duplicate it: %r",
                                          self.rule['detection_public_id'], e)
                alert_id = uuid.uuid4().hex
            try:
                self.write(alert_id, self.payload(match))
            except ElasticsearchException as e:
                # EAException makes ElastAlert retry
                raise EAException(f"Unable to write the alert to Elasticsearch: {str(e)[:ERROR_TEXT_LIMIT]}") from e

    def payload(self, match):
        rule_info = {
            "name": self.rule['detection_title'],
            "uuid": self.rule['detection_public_id']
        }

        # Add optional fields if they are present in the rule
        for field in self.optional_fields:
            rule_key = field.split('_')[-1]  # Assumes field format "sigma_<key>"
            if field in self.rule:
                rule_info[rule_key] = self.rule[field]

        event_info = {
            "kind": "alert",
            "severity": self.rule['event.severity'],
            "module": self.rule['event.module'],
            "dataset": self.rule['event.dataset'],
            "severity_label": self.rule['sigma_level']
        }

        payload = {
            "tags": ["alert"],
            "rule": rule_info,
            "event": event_info,
            "sigma_level": self.rule['sigma_level'],
            "event_data": self.event_data(match),
            "@timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        }

        if self.is_correlation:
            keys = self.query_keys()
            try:
                # built before any is added, so a failure adds none
                reason = self.summary(match)
                labels = {"correlation_group_by": ', '.join(keys), "correlation_group": self.group(match)} if keys else None
                related = self.related(match)
            except MATCH_ERRORS as e:
                elastalert_logger.warning("Writing alert for rule %s without its correlation summary: %r",
                                          self.rule['detection_public_id'], e)
            else:
                payload["event"]["reason"] = reason
                if labels:
                    payload["labels"] = labels
                if related:
                    payload["related"] = related

        return payload

    def write(self, alert_id, payload):
        try:
            self.create(alert_id, payload)
        except RequestError as e:
            # mapping rejections come from event_data; retry it as text
            rejection = str(e)[:ERROR_TEXT_LIMIT]
            try:
                self.create(alert_id, self.without_event_data(payload, rejection))
            except RequestError as again:
                elastalert_logger.error("Dropping alert %s for rule %s, rejected by Elasticsearch even without its event data: %s; first rejection: %s",
                                        alert_id, self.rule['detection_public_id'], str(again)[:ERROR_TEXT_LIMIT], rejection)
                return
            elastalert_logger.warning("Stored alert %s for rule %s with its event data as text, rejected by Elasticsearch: %s",
                                      alert_id, self.rule['detection_public_id'], rejection)

    def create(self, alert_id, payload):
        try:
            self.es.create(index=ALERT_INDEX, id=alert_id, body=payload)
        except ConflictError:
            pass  # a repeat id is already stored

    @staticmethod
    def without_event_data(payload, rejection):
        """Moves event_data to event.original; the tag keeps Fleet's final pipeline from dropping it."""
        fallback = {k: v for k, v in payload.items() if k != 'event_data'}
        fallback['event'] = dict(payload['event'], original=json.dumps(payload['event_data'], cls=DateTimeEncoder))
        fallback['error'] = {'message': f"event_data rejected by Elasticsearch: {rejection}"}
        fallback['tags'] = payload['tags'] + ['preserve_original_event']
        return fallback

    def get_info(self):
        return {'type': 'SecurityOnionESAlerter'}
