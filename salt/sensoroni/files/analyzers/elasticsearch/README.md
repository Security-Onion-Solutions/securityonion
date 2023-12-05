# Elasticsearch
Elasticsearch returns an informational breakdown of the queried observable.

## Overview
Elasticsearch supports queries towards user's database:
User can use these observable type to query :hash, domain, file, filename, fqdn, gimphash, ip, mail, mail_subject, regexp, registry, telfhash, tlsh, uri_path, url, and user-agent values

## Description
Configured, and submit the field you want to search for in your database. Ex:domain, hash, IP, or URL

## Requirement
An API key or Credentials is necessary for utilizing Elasticsearch.

## Configuration Requirements
``api_key`` - API key used for communication with the Elastic Search API
``auth_user``          - Username used for communication with elasticsearch database
``auth_pwd``           - password used for communication with elasticsearch
``base_url``          - URL that connect to Elasticsearch VM on port 9200. Example format :"https://<your IP address>:9200
``index``             -the index of the data in Elasticsearch database. Default value is _all
``num_results``        -the max number of results will be displayed
``time_delta_minutes``  -Range of time the users want the data. The value is in minutes and will be converted to days. Defaults value is is 1440
``timestamp_field_name``-the name of your timestamp field name. Default value is @timestamp
``map``               -this is the dictionary of the field name in the user's Elasticsearch database. Example value {"hash":"userhashfieldname"}. This value will map the Security Onion hash field name to user hash field name.
``cert_path``         -this is the path to the certificate in the host for authentication purpose 
This value should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    elasticsearch:
      base_url:$yourbase_url
      api_key: $yourapi_key
      numResults:$yournum_results
      auth_user:$yourauth_user
      auth_pwd:$yourauth_pwd
      index:$yourindex
      timeDeltaMinutes:$yourtime_delta_minutes
      timestampFieldName:$yourtimestamp_field_name
      cert_path:$yourcert_path
      map:$yourmap
```
