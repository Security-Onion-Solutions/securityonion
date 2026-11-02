# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
# https://securityonion.net/license; you may not use this file except in compliance with the
# Elastic License 2.0.

from datetime import datetime
import json
import logging
import sys
import types

# stand-ins when ElastAlert isn't installed (CI)
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

    def lookup_es_key(doc, term):
        for part in term.split('.'):
            if not isinstance(doc, dict) or part not in doc:
                return None
            doc = doc[part]
        return doc

    def ts_to_dt(value):
        return value if isinstance(value, datetime) else datetime.fromisoformat(value)

    def elasticsearch_client(conf):
        return None  # tests set the alerter's client

    alerts = types.ModuleType('elastalert.alerts')
    alerts.Alerter = Alerter
    alerts.DateTimeEncoder = DateTimeEncoder
    util = types.ModuleType('elastalert.util')
    util.EAException = EAException
    util.elastalert_logger = logging.getLogger('elastalert')
    util.lookup_es_key = lookup_es_key
    util.ts_to_dt = ts_to_dt
    util.elasticsearch_client = elasticsearch_client
    package = types.ModuleType('elastalert')
    package.alerts = alerts
    package.util = util
    sys.modules.update({'elastalert': package, 'elastalert.alerts': alerts, 'elastalert.util': util})

# stand-ins when elasticsearch-py isn't installed (CI)
try:
    import elasticsearch.exceptions  # noqa: F401
except ImportError:

    class ElasticsearchException(Exception):
        pass

    class TransportError(ElasticsearchException):
        pass

    class ConnectionError(TransportError):
        pass

    class ConflictError(TransportError):
        pass

    class RequestError(TransportError):
        pass

    exceptions = types.ModuleType('elasticsearch.exceptions')
    for cls in (ElasticsearchException, TransportError, ConnectionError, ConflictError, RequestError):
        setattr(exceptions, cls.__name__, cls)
    es_package = types.ModuleType('elasticsearch')
    es_package.exceptions = exceptions
    sys.modules.update({'elasticsearch': es_package, 'elasticsearch.exceptions': exceptions})
