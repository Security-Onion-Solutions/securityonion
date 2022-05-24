# Greynoise

## Description
Submit an IP address to Greynoise for analysis.

## Configuration Requirements

``api_key`` - API key used for communication with the Greynoise API
``api_version`` - Version of Greynoise API. Default is ``community``


This value should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    greynoise:
      api_key: $yourapikey
```
