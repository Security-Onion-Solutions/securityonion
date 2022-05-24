# EmailRep

## Description
Submit an email address to EmailRepIO for analysis.

## Configuration Requirements

``api_key`` - API key used for communication with the EmailRepIO API

This value should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    emailrep:
      api_key: $yourapikey
```
