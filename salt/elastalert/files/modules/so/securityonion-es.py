# -*- coding: utf-8 -*-

# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at 
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.


from datetime import datetime
from time import gmtime, strftime
import hashlib
import ipaddress
import re
import requests,json
from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityOnionESAlerter(Alerter):
    """
    Use matched data to create alerts in Elasticsearch.
    """

    required_options = set(['detection_title', 'sigma_level'])
    optional_fields = ['sigma_category', 'sigma_product', 'sigma_service', 'sigma_correlation']

    count_labels = {
        'event_count': '%count% events',
        'value_count': '%count% distinct values',
        'event_type_count': '%count% correlated rules matched',
        'value_sum': 'total %count%',
        'value_avg': 'average %count%',
        'value_percentile': 'percentile %count%',
        'value_median': 'median %count%',
    }
    placeholder = re.compile(r'%([^%\s]+)%')
    # group-by fields copied into ECS related.*
    related_users = {'user.name', 'winlog.event_data.TargetUserName', 'winlog.event_data.SubjectUserName'}
    related_hosts = {'host.name', 'host.hostname', 'winlog.computer_name'}

    @staticmethod
    def lookup(doc, dotted):
        """ Resolve a dotted path; ES|QL columns arrive nested. """
        node = doc
        for part in dotted.split('.'):
            if not isinstance(node, dict) or part not in node:
                return None
            node = node[part]
        return node

    def query_keys(self):
        """ compound_query_key holds the list; query_key is flattened to a string. """
        return self.rule.get('compound_query_key') or ([self.rule['query_key']] if self.rule.get('query_key') else [])

    def alert_id(self, match):
        """ Stable id: window + group values for correlations, source _id otherwise. """
        keys = self.query_keys()
        if keys:
            values = '|'.join(str(self.lookup(match, k)) for k in keys)
            key = f"{self.rule['detection_public_id']}|{self.to_dt(match['@timestamp']).isoformat()}|{values}"
        else:
            key = f"{self.rule['detection_public_id']}|{match.get('_id')}"

        return hashlib.sha256(key.encode('utf-8')).hexdigest()

    def group(self, match):
        """ Group-by values joined as ElastAlert joins them for the realert silence key. """
        return ', '.join(str(self.lookup(match, k)) for k in self.query_keys())

    def related_bucket(self, key):
        if key == 'ip' or key.endswith('.ip'):
            return 'ip'
        if key in self.related_users or key.endswith('.user.name'):
            return 'user'
        if key in self.related_hosts:
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
        """ ECS related.* from group-by values; invalid IPs are skipped, as they fail the ip mapping. """
        related = {}
        for key in self.query_keys():
            bucket = self.related_bucket(key)
            if not bucket:
                continue
            value = self.lookup(match, key)
            for v in value if isinstance(value, list) else [value]:
                if v is None or (bucket == 'ip' and not self.valid_ip(str(v))):
                    continue
                related.setdefault(bucket, {})[str(v)] = None
        return {bucket: list(values) for bucket, values in related.items()}

    def event_data(self, match):
        """ The match without the compound query_key field, which ES would map by its last part (e.g. .ip). """
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

    @staticmethod
    def to_dt(value):
        # ES|QL gives ISO strings; ElastAlert parses @timestamp, except on a retried alert.
        return value if isinstance(value, datetime) else datetime.fromisoformat(value)

    def summary(self, match):
        """ One-line correlation summary; None for single-event rules. """
        if 'window_start' not in match:
            return None

        start = self.to_dt(match['window_start'])
        end = self.to_dt(match['@timestamp'])
        name = next((f for f in self.count_labels if f in match), None)
        values = {
            'count': self.format_count(match.get(name)),
            'start': start.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'end': end.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'duration': self.format_duration(int((end - start).total_seconds())),
        }

        template = self.rule.get('summary_template')
        if not template:
            groups = ', '.join(f"{k} %{k}%" for k in self.query_keys())
            template = f"{self.count_labels.get(name, '%count%')}{' for ' + groups if groups else ''} in %duration%"

        def fill(m):
            if m[1] in values:
                return values[m[1]]
            value = self.lookup(match, m[1])
            # unknown placeholders stay visible so typos show
            return m[0] if value is None else self.format_value(value)

        return self.placeholder.sub(fill, template)

    def alert(self, matches):
        for match in matches:
            timestamp = strftime("%Y-%m-%d"'T'"%H:%M:%S"'.000Z', gmtime())
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

            event_info = {
                "kind": "alert",
                "severity": self.rule['event.severity'],
                "module": self.rule['event.module'],
                "dataset": self.rule['event.dataset'],
                "severity_label": self.rule['sigma_level']
            }

            reason = self.summary(match)
            if reason:
                event_info["reason"] = reason

            # Construct the payload with the conditional rule_info
            payload = {
                "tags": ["alert"],
                "rule": rule_info,
                "event": event_info,
                "sigma_level": self.rule['sigma_level'],
                "event_data": self.event_data(match),
                "@timestamp": timestamp
            }

            keys = self.query_keys()
            if keys:
                payload["labels"] = {
                    "correlation_group_by": ', '.join(keys),
                    "correlation_group": self.group(match),
                }
                related = self.related(match)
                if related:
                    payload["related"] = related
            alert_id = self.alert_id(match)
            # _create returns 409 on a repeat id; EAException makes ElastAlert retry
            url = (f"https://{self.rule['es_host']}:{self.rule['es_port']}"
                   f"/logs-detections.alerts-so/_create/{alert_id}")
            response = self.put_alert(url, payload)
            if response.status_code == 400:
                # mapping rejections come from event_data; retry with it as unindexed text
                rejection = response.text[:500]
                payload = self.without_event_data(payload, rejection)
                response = self.put_alert(url, payload)
                if response.status_code == 400:
                    elastalert_logger.error("Dropping alert %s for rule %s, rejected by Elasticsearch even without its event data: %s; first rejection: %s",
                                            alert_id, self.rule['detection_public_id'], response.text[:500], rejection)
                    continue
                elastalert_logger.warning("Stored alert %s for rule %s with its event data as text, rejected by Elasticsearch: %s",
                                          alert_id, self.rule['detection_public_id'], rejection)
            if response.status_code != 409 and not response.ok:
                raise EAException(f"Unable to write alert: {response.status_code} {response.text[:500]}")

    def put_alert(self, url, payload):
        creds = None
        if 'es_username' in self.rule and 'es_password' in self.rule:
            creds = (self.rule['es_username'], self.rule['es_password'])
        try:
            return requests.put(url, data=json.dumps(payload, cls=DateTimeEncoder),
                                headers={"Content-Type": "application/json"}, verify=False, auth=creds)
        except requests.RequestException as e:
            raise EAException(f"Unable to write alert: {e}")

    @staticmethod
    def without_event_data(payload, rejection):
        """ event_data moved to event.original; the tag keeps Fleet's final pipeline from removing it. """
        fallback = {k: v for k, v in payload.items() if k != 'event_data'}
        fallback['event'] = dict(payload['event'], original=json.dumps(payload['event_data'], cls=DateTimeEncoder))
        fallback['error'] = {'message': f"event_data rejected by Elasticsearch: {rejection}"}
        fallback['tags'] = payload['tags'] + ['preserve_original_event']
        return fallback

    def get_info(self):
        return {'type': 'SecurityOnionESAlerter'}
