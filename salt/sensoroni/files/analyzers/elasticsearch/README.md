# Elasticsearch
Elasticsearch returns an informational breakdown of the queried observable.

## Overview
Elasticsearch facilitates queries within the user's database. User can use these observable type: hash, domain, file, filename, fqdn, gimphash, IP, mail, mail_subject, regexp, registry, telfhash, tlsh, uri_path, URL, and user-agent values.

## Description
Configure and submit the field you want to search for in your database. Ex: domain, hash, IP, or URL

## Requirement
An API key or User Credentials is necessary for utilizing Elasticsearch.

## Configuration Requirements

In SOC, navigate to `Administration`, toggle `Show all configurable settings, including advanced settings.`, and navigate to `sensoroni` -> `analyzers` -> `elasticsearch`.

![image](https://github.com/Security-Onion-Solutions/securityonion/blob/2.4/dev/assets/images/screenshots/analyzers/elasticsearch.png?raw=true)


The following configuration options are available for:

``api_key`` - API key used for communication with the Elasticsearch API (Optional if auth_user and auth_pwd are used)

``auth_user`` - Username used for communication with Elasticsearch 

``auth_pwd`` - Password used for communication with Elasticsearch

``base_url`` - URL that connect to Elasticsearch VM on port 9200. Example format :"https://<your IP address>:9200

``index`` - The index of the data in Elasticsearch database. Default value is _all.

``num_results`` - The max number of results will be displayed. Default value is 10.

``time_delta_minutes`` - Range of time the users want the data in minutes. The value is in minutes and will be converted to days. Defaults value is is 1440.

``timestamp_field_name`` - The name of your timestamp field name. Default value is @timestamp.

``map`` - This is the dictionary of the field name in the user's Elasticsearch database. Example value {"hash":"userhashfieldname"}. This value will map the Security Onion hash field name to user hash field name.

``cert_path`` - This is the path to the certificate in the host for authentication purpose (Required)

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
