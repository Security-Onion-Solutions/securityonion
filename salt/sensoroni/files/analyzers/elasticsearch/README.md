# Elasticsearch
==========

From https://www.elastic.co/elasticsearch/:

    
    Elasticsearch is a distributed, RESTful search and analytics
    engine capable of addressing a growing number of use cases.
    As the heart of the Elastic Stack, it centrally stores your
    data for lightning fast search, fine‑tuned relevancy, and
    powerful analytics that scale with ease.

An API key is necessary for utilizing Elasticsearch.

## Installation
------------

In order to begin, we will need to make sure we satisfy a few prerequisites:

| **Elasticsearch API key** - can be obtained at:
  https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html

| **Elasticsearch VM** - follow the instructions here:
  https://github.com/peasead/elastic-container

| **An active connection to an Elasticsearch VM** - to make queries

## Configuration Requirements
``authUser``          - Username used for communication with elasticsearch database
``authPWD``           - password used for communication with elasticsearch
``base_url``          - URL that connect to Elasticsearch VM on port 9200. Example format :"https://<your IP address>:9200
``index``             -the index of the data in Elasticsearch database. Default value is _all
``numResults``        -the max number of results will be displayed
``timeDeltaMinutes``  -Range of time the users want the data. The value is in minutes and will be converted to days. Defaults value is is 1440
``timestampFieldName``-the name of your timestamp field name. Default value is @timestamp
``map``               -this is the dictionary of the field name in the user's Elasticsearch database. Example value {"hash":"userhashfieldname"}. This value will map the Security Onion hash field name to user hash field name.

This value should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    elasticsearch:
      api_key: $yourapikey
      numResults:$yournumResults
      index:$yourindex
      timeDeltaMinutes:$yourtimeDeltaMinutes
      timestampFieldName:$yourtimestampFieldName
```
## Description
------------
Elasticsearch supports queries towards user's database:
User can use these observable type to query :hash, domain, file, filename, fqdn, gimphash, ip, mail, mail_subject, regexp, registry, telfhash, tlsh, uri_path, url, and user-agent values

Elasticsearch returns an informational breakdown of the queried observable.
