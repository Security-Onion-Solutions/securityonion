# EchoTrail
==========

## Description
Echotrail supports queries towards:

::

   Filename, Hash, and Commandline values

Echotrail returns an informational breakdown of the queried observable.


Installation
------------

An API key is necessary for utilizing Echotrail.

In order to begin, we will need to make sure we satisfy a few prerequisites:

| **Echotrail API key** - can be obtained for free after making an account at:
  https://www.echotrail.io/register. Note if used for commercial, user need to paid for subcribtion

| **External internet access** - to make queries

## Configuration Requirements
``api_key`` - API key used for communication with the Echotrail API
This value should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    echotrail:
      api_key: $yourapikey
```