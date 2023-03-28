# Urlscan

## Description
Submit a URL to Urlscan for analysis.

## Configuration Requirements

``api_key`` - API key used for communication with the urlscan API
``enabled`` - Determines whether or not the analyzer is enabled. Defaults to ``False``
``visibility`` - Determines whether or not scan results are visibile publicly. Defaults to ``public``
``timeout`` - Time to wait for scan results. Defaults to ``180``s

This value should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    urlscan:
      api_key: $yourapikey
```
