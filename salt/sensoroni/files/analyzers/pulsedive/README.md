# Pulsedive

## Description
Search Pulsedive for a domain, hash, IP, URI, URL, or User Agent.

## Configuration Requirements

``api_key`` - API key used for communication with the Virustotal API

This value should be set in the pillar, like so:

```
sensoroni:
  analyzers:
    pulsedive:
      api_key: $yourapikey
```
