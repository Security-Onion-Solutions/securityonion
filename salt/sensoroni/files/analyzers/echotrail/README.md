# EchoTrail


## Description
Submit a filename, hash, commandline to Echo Trail for analysis

## Configuration Requirements
``api_key`` - API key used for communication with the Echotrail API

This value should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    echotrail:
      api_key: $yourapikey
```