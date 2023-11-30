#Elasticsearch
==========

From
https://www.elastic.co/elasticsearch/:

    
    Elasticsearch is a distributed, RESTful search and analytics
    engine capable of addressing a growing number of use cases.
    As the heart of the Elastic Stack, it centrally stores your
    data for lightning fast search, fine‑tuned relevancy, and
    powerful analytics that scale with ease.

An API key is necessary for utilizing Elasticsearch.

Installation
------------

In order to begin, we will need to make sure we satisfy a few prerequisites:

| **Elasticsearch API key** - can be obtained at:
  https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html

| **Elasticsearch VM** - follow the instructions here:
  https://github.com/peasead/elastic-container

| **An active connection to an Elasticsearch VM** - to make queries


Overview
------------
Elasticsearch supports queries towards:

::

   hash, domain, file, filename, fqdn, gimphash, ip, mail, mail_subject, regexp, registry, telfhash, tlsh, uri_path, url, and user-agent values

Elasticsearch returns an informational breakdown of the queried observable.
