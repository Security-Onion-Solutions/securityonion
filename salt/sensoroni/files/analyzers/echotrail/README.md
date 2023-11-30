#Echotrail
==========

From
https://www.echotrail.io/docs/insights:

    
    Using the EchoTrail API, you can search for Windows filenames or hashes. 
    Echotrail will return a summary of the statistical information that 
    describes the behavior of that particular filename or hash based on 
    the data we've collected from our sensors over time. If you only need a 
    subset of the results, or if you want to subsearch outside the truncated
    table, then you can use the subsearches.

An API key is necessary for utilizing Echotrail.

Installation
------------

In order to begin, we will need to make sure we satisfy a few prerequisites:

| **Echotrail API key** - can be obtained for free after making an account at:
  https://www.echotrail.io/register

| **External internet access** - to make queries


Overview
------------
Echotrail supports queries towards:

::

   Filename, Hash, and Commandline values

Echotrail returns an informational breakdown of the queried observable.
