# Virustotal

## Description
Submit a domain, hash, IP, or URL to Virustotal for analysis.

## Configuration Requirements

``api_key`` - API key used for communication with the Virustotal API

This value should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    virustotal:
      api_key: $yourapikey
```
