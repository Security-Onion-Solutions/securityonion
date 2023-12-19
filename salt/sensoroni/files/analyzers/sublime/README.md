# Sublime

## Description
Submit a base64-encoded EML file to Sublime Platform for analysis.

## Configuration Requirements
In SOC, navigate to `Administration`, toggle `Show all configurable settings, including advanced settings.`, and navigate to `sensoroni` -> `analyzers` -> `sublime_platform`.

![image](https://github.com/Security-Onion-Solutions/securityonion/blob/2.4/dev/assets/images/screenshots/analyzers/sublime.png?raw=true)


The following configuration options are available for:

``api_key`` - API key used for communication with the Sublime Platform API (Required)

``base_url`` -  URL used for communication with Sublime Platform. If no value is supplied, the default of `https://api.platform.sublimesecurity.com` will be used.

The following options relate to [Live Flow](https://docs.sublimesecurity.com/reference/analyzerawmessageliveflow-1) analysis only:

``live_flow`` - Determines if live flow analysis should be used. Defaults to `False`.

``mailbox_email_address`` - The mailbox address to use for during live flow analysis. (Required for live flow analysis)

``message_source_id`` - The ID of the message source to use during live flow analysis. (Required for live flow analysis)
