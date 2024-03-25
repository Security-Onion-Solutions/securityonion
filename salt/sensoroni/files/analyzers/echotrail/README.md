# EchoTrail


## Description
Submit a filename, hash, commandline to EchoTrail for analysis

## Configuration Requirements

In SOC, navigate to `Administration`, toggle `Show all configurable settings, including advanced settings.`, and navigate to `sensoroni` -> `analyzers` -> `echotrail`.
![echotrail](https://github.com/Security-Onion-Solutions/securityonion/blob/2.4/dev/assets/images/screenshots/analyzers/echotrail.png?raw=true)


The following configuration options are available for:

``api_key`` - API key used for communication with the Echotrail API (Required)

This value should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    echotrail:
      api_key: $yourapikey
```
