# EchoTrail


## Description
Submit a filename, hash, commandline to EchoTrail for analysis

## Configuration Requirements

In SOC, navigate to `Administration`, toggle `Show all configurable settings, including advanced settings.`, and navigate to `sensoroni` -> `analyzers` -> `echotrail`.

![echotrail](https://github.com/RyHoa/securityonion/assets/129560634/43b55869-1fba-4907-8418-c0745c37237b)


The following configuration options are available for:

``api_key`` - API key used for communication with the Echotrail API (Required)

This value should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    echotrail:
      api_key: $yourapikey
```
