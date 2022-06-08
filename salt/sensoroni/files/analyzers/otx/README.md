# Alienvault OTX

## Description
Submit a domain, hash, IP, or URL to Alienvault OTX for analysis.

## Configuration Requirements

``api_key`` - API key used for communication with the Alienvault API

This value should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    otx:
      api_key: $yourapikey
```
