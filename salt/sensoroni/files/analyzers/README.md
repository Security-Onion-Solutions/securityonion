# Security Onion Analyzers

Security Onion provides a means for performing data analysis on varying inputs. This data can be any data of interest sourced from event logs. Examples include hostnames, IP addresses, file hashes, URLs, etc. The analysis is conducted by one or more analyzers that understand that type of input. Analyzers come with the default installation of Security Onion. However, it is also possible to add additional analyzers to extend the analysis across additional areas or data types.

## Supported Observable Types
The built-in analyzers support the following observable types:

| Name                    | Domain | Hash  | IP    | Mail  | Other | URI   |  URL  | User Agent |
| ------------------------|--------|-------|-------|-------|-------|-------|-------|-------|
| Alienvault OTX          |&check; |&check;|&check;|&cross;|&cross;|&cross;|&check;|&cross;|
| EmailRep                |&cross; |&cross;|&cross;|&check;|&cross;|&cross;|&cross;|&cross;|
| Greynoise               |&cross; |&cross;|&check;|&cross;|&cross;|&cross;|&cross;|&cross;|
| LocalFile               |&check; |&check;|&check;|&cross;|&check;|&cross;|&check;|&cross;|
| Malware Hash Registry   |&cross; |&check;|&cross;|&cross;|&cross;|&cross;|&check;|&cross;|
| Pulsedive               |&check; |&check;|&check;|&cross;|&cross;|&check;|&check;|&check;|
| Spamhaus                |&cross; |&cross;|&check;|&cross;|&cross;|&cross;|&cross;|&cross;|
| Urlhaus                 |&cross; |&cross;|&cross;|&cross;|&cross;|&cross;|&check;|&cross;|
| Urlscan                 |&cross; |&cross;|&cross;|&cross;|&cross;|&cross;|&check;|&cross;|
| Virustotal              |&check; |&check;|&check;|&cross;|&cross;|&cross;|&check;|&cross;|
| WhoisLookup             |&check; |&cross;|&cross;|&cross;|&cross;|&check;|&cross;|&cross;|

## Authentication
Many analyzers require authentication, via an API key or similar. The table below illustrates which analyzers require authentication.

| Name                    | Authn Req'd|
--------------------------|------------|
[AlienVault OTX](https://otx.alienvault.com/api)            |&check;|
[EmailRep](https://emailrep.io/key)                  |&check;|
[GreyNoise](https://www.greynoise.io/plans/community)                 |&check;|
LocalFile                 |&cross;|
[Malware Hash Registry](https://hash.cymru.com/docs_whois)    |&cross;|
[Pulsedive](https://pulsedive.com/api/)                 |&check;|
[Spamhaus](https://www.spamhaus.org/dbl/)                  |&cross;|
[Urlhaus](https://urlhaus.abuse.ch/)                   |&cross;|
[Urlscan](https://urlscan.io/docs/api/)                   |&check;|
[VirusTotal](https://developers.virustotal.com/reference/overview)                |&check;|
[WhoisLookup](https://github.com/meeb/whoisit)           |&cross;|


## Developer Guide

### Python

Analyzers are Python modules, and can be made up of a single .py script, for simpler analyzers, or a complex set of scripts organized within nested directories.

The Python language was chosen because of it's wide adoption in the security industry, ease of development and testing, and the abundance of developers with Python skills.

Specifically, analyzers must be compatible with Python 3.10.

For more information about Python, see the [Python Documentation](https://docs.python.org).

### Development

Custom analyzers should be developed outside of the Security Onion cluster, in a proper software development environment, with version control or other backup mechanisms in place. The analyzer can be developed, unit tested, and integration tested without the need for a Security Onion installation. Once satisifed with the analyzer functionality the analyzer directory should be copied to the Security Onion manager node. 

Developing an analyzer directly on a Security Onion manager node is strongly discouraged, as loss of source code (and time and effort) can occur, should the management node suffer a catastrophic failure with disk storage loss.

For best results, avoid long, complicated functions in favor of short, discrete functions. This has several benefits:

- Easier to troubleshoot
- Easier to maintain
- Easier to unit test
- Easier for other developers to review

### Linting

Source code should adhere to the [PEP 8 - Style Guide for Python Code](https://peps.python.org/pep-0008/). Developers can use the default configuration of `flake8` to validate conformance, or run the included `build.sh` inside the analyzers directory. Note that linting conformance is mandatory for analyzers that are contributed back to the Security Onion project.

### Testing

Python's [unitest](https://docs.python.org/3/library/unittest.html) library can be used for covering analyzer code with unit tests. Unit tests are encouraged for custom analyzers, and mandatory for public analyzers submitted back to the Security Onion project.

If you are new to unit testing, please see the included `urlhaus_test.py` as an example.

Unit tests should be named following the pattern `<scriptname>_test.py`.


### Analyzer Package Structure

Delpoyment of a custom analyzer entails copying the analyzer source directory and depenency wheel archives to the Security Onion manager node. The destination locations can be found inside the `securityonion` salt source directory tree. Using the [Saltstack](https://github.com/saltstack/salt) directory pattern allows Security Onion developers to add their own analyzers with minimal additional effort needed to upgrade to newer versions of Security Onion. When the _sensoroni_ salt state executes it will merge the default analyzers with any local analyzers, and copy the merged analyzers into the `/opt/so/conf/sensoroni` directory. 

Do not modify files in the `/opt/so/conf/sensoroni` directory! This is a generated directory and changes made inside will be automatically erased on a frequent interval. 

On a Security Onion manager, custom analyzers should be placed inside the `/opt/so/saltstack/local/salt/sensoroni` directory, as described in the next section.

#### Directory Tree

From within the default saltstack directory, the following files and directories exist:

```
salt
  |- sensoroni
        |- files
              |- analyzers
                    |- urlhaus                    <- Example of an existing analyzer
                    |     |- source-packages      <- Contains wheel package bundles for this analyzer's dependencies
                    |     |- site-packages        <- Auto-generated site-packages directory (or used for custom dependencies)
                    |     |- requirements.txt     <- List of all dependencies needed for this analyzer
                    |     |- urlhaus.py           <- Source code for the analyzer
                    |     |- urlhaus_test.py      <- Unit tests for the analyzer source code
                    |     |- urlhaus.json         <- Metadata for the analyzer
                    |     |- __init__.py          <- Package initialization file, often empty
                    |
                    |- build.sh                   <- Simple CI tool for validating linting and unit tests
                    |- helpers.py                 <- Common functions shared by many analyzers
                    |- helpers_test.py            <- Unit tests for the shared source code
                    |- pytest.ini                 <- Configuration options for the flake8 and pytest
                    |- README.md                  <- The file you are currently reading
```

Custom analyzers should conform to this same structure, but instead of being placed in the `/opt/so/saltstack/default` directory tree, they should be placed in the `/opt/so/saltstack/local` directory tree. This ensures future Security Onion upgrades will not overwrite customizations. Shared files like `build.sh` and `helpers.py` do not need to be duplicated. They can remain in the _default_ directory tree. Only new or modified files should exist in the _local_ directory tree.

#### Metadata

Each analyzer has certain metadata that helps describe the function of the analyzer, required inputs, artifact compatibility, optional configuration options, analyzer version, and other important details of the analyzer. This file is a static file and is not intended to be used for dynamic or custom configuration options. It should only be modified by the author of the analyzer.

The following example describes the urlhaus metadata content:

```
{
  "name": "Urlhaus",                                  <- Unique human-friendly name of this analyzer
  "version": "0.1",                                   <- The version of the analyzer
  "author": "Security Onion Solutions",               <- Author's name, and/or email or other contact information
  "description": "This analyzer queries URLHaus...",  <- A brief, concise description of the analyzer
  "supportedTypes" :  ["url"],                        <- List of types that must match the SOC observable types
  "baseUrl": "https://urlhaus-api.abuse.ch/v1/url/"   <- Optional hardcoded data used by the analyzer
}
```

The `supportedTypes` values should only contain the types that this analyzer can work with. In the case of the URLHaus analyzer, we know that it works with URLs. So adding "hash" to this list wouldn't make sense, since URLHaus doesn't provide information about file hashes. If an analyzer does not support a particular type then it will not show up in the analyzer results in SOC for that observable being analyzed. This is intentional, to eliminate unnecessary screen clutter in SOC. To find a list of available values for the `supportedTypes` field, login to SOC and inside of a Case, click the + button on the Observables tab. You will see a list of types and each of those can be used in this metadata field, when applicable to the analyzer.

#### Dependencies

Analyzers will often require the use of third-party packages. For example, if an analyzer needs to make a request to a remote server via HTTPS, then the `requests` package will likely be used. Each analyzer will container a `requirements.txt` file, in which all third-party dependencies can be specified, following the python [Requirements File Specification](https://pip.pypa.io/en/stable/reference/requirements-file-format/).

Additionally, to support airgapped users, the dependency packages themselves, and any transitive dependencies, should be placed inside the `source-packages` directory. To obtain the full hierarchy of dependencies, execute the following commands:

```bash
pip download -r <my-analyzer-path>/requirements.txt -d <my-analyzer-path>/source-packages
```


### Analyzer Architecture

The Sensoroni Docker container is responsible for executing analyzers. Only the manager's Sensoroni container will process analyzer jobs. Other nodes in the grid, such as sensors and search nodes, will not be assigned analyzer jobs.

When the Sensoroni Docker container starts, the `/opt/so/conf/sensoroni/analyzer` directory is mapped into the container. The initialization of the Sensoroni Analyze module will scan that directory for any subdirectories. Valid subdirectories will be added as an available analyzer.

The analyzer itself will only run when a user in SOC enqueues an analyzer job, such as via the Cases -> Observables tab. When the Sensoroni node is ready to run the job it will execute the python command interpretor separately for each loaded analyzer. The command line resembles the following:

```bash
python -m urlhaus '{"artifactType":"url","value":"https://bigbadbotnet.invalid",...}'
```

It is up to each analyzer to determine whether the provided input is compatible with that analyzer. This is assisted by the analyzer metadata, as described earlier in this document, with the use of the `supportedTypes` list.

Once the analyzer completes its functionality, it must terminate promptly. See the following sections for more details on expected internal behavior of the analyzer.

#### Configuration

Analyzers may need dynamic configuration data, such as credentials or other secrets, in order to complete their function. Optional configuration files can provide this information, and are expected to reside in the analyzer's directory. Configuration files are typically written in YAML syntax for ease of modification.

Configuration files for analyzers included with Security Onion will be pillarized, meaning they derive their custom values from the Saltstack pillar data. For example, an analyzer that requires a user supplied credential might contain a config file resembling the following, where Jinja templating syntax is used to extra Salt pillar data:

```yaml
username: {{ salt['pillar.get']('sensoroni:analyzers:myanalyzer:username', '') }}
password: {{ salt['pillar.get']('sensoroni:analyzers:myanalyzer:password', '') }}
```

Sensoroni will not provide any inputs to the analyzer during execution, other than the artifact input in JSON format. However, developers will likely need to test the analyzer outside of Sensoroni and without Jinja templating, therefore an alternate config file should normally be supplied as the configuration argument during testing. Analyzers should allow for this additional command line argument, but by default should automatically read a configuration file stored in the analyzer's directory.

#### Exit Code

If an analyzer determines it cannot or should not operate on the input then the analyzer should return an exit code of `126`.

If an analyzer does attempt to operate against the input then the exit code should be 0, regardless of the outcome. The outcome, be it an error, a confirmed threat detection, or perhaps an unknown outcome, should be noted in the output of the analyzer.

#### Output

The outcome of the analyzer is reflected in the analyzer's output to `stdout`. The output must be JSON formatted, and should contain the following fields.

`summary`: A very short summarization of the outcome. This should be under 50 characters, otherwise it will be truncated when displayed on the Analyzer job list.

`status`: Can be one of the following status values, which most appropriately reflects the outcome:
- `ok`: The analyzer has concluded that the provided input is not a known threat.
- `info`: This analyzer provides informative data, but does not attempt to conclude the input is a threat.
- `caution`: The data provided is inconclusive. Analysts should review this information further. This can be used in error scenarios, such as if the analyzer fails to complete, perhaps due to a remote service being offline.
- `threat`: The analyzer has detected that the input is likely related to a threat.

`error`: [Optional] If the analyzer encounters an unrecoverable error, those details, useful for administrators to troubleshoot the problem, should be placed in this field.

Additional fields are allowed, and should contain data that is specific to the analyzer. 

Below is an example of a _urlhaus_ analyzer output. Note that the urlhaus raw JSON is added to a custom field called "response".

```json
{
  "response": {
    "blacklists": {
      "spamhaus_dbl": "not listed",
      "surbl": "not listed"
    },
    "date_added": "2022-04-07 12:39:14 UTC",
    "host": "abeibaba.com",
    "id": "2135795",
    "larted": "false",
    "last_online": null,
    "payloads": null,
    "query_status": "ok",
    "reporter": "switchcert",
    "tags": [
      "Flubot"
    ],
    "takedown_time_seconds": null,
    "threat": "malware_download",
    "url": "https://abeibaba.com/ian/?redacted",
    "url_status": "offline",
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/2135795/"
  },
  "status": "threat",
  "summary": "malware_download"
}
```

Users in SOC will be able to view the entire JSON output, therefore it is important that sensitive information, such as credentials or other secrets, is excluded from the output.

#### Internationalization

Some of the built-in analyzers use snake_case summary values, instead of human friendly words or phrases. These are identifiers that the SOC UI will use to lookup a localized translation for the user. The use of these identifiers is not required for custom analyzers. In fact, in order for an identifier to be properly localized the translations must exist in the SOC product, which is out of scope of this development guide. That said, the following generic translations might be useful for custom analyzers:

| Identifier         | English                    |
| ------------------ | -------------------------- |
| `malicious`        | Malicious                  |
| `suspicious`       | Suspicious                 |
| `harmless`         | Harmless                   |
| `internal_failure` | Analyzer Internal Failure  |
| `timeout`          | Remote Host Timed Out      |

#### Timeout

It is expected that analyzers will finish quickly, but there is a default timeout in place that will abort the analyzer if the timeout is exceeded. By default that timeout is 15 minutes (900000 milliseconds), but can be customized via the `sensoroni:analyze_timeout_ms` salt pillar.


## Contributing

Review the Security Onion project [contribution guidelines](https://github.com/Security-Onion-Solutions/securityonion/blob/master/CONTRIBUTING.md) if you are considering contributing an analyzer to the Security Onion project.

#### Procedure

In order to make a custom analyzer into a permanent Security Onion analyzer, the following steps need to be taken:

1. Fork the [securityonion GitHub repository](https://github.com/Security-Onion-Solutions/securityonion)
2. Copy your custom analyzer directory to the forked project, under the `securityonion/salt/sensoroni/files/analyzers` directory.
3. Ensure the contribution requirements in the following section are met.
4. Submit a [pull request](https://github.com/Security-Onion-Solutions/securityonion/pulls) to merge your GitHub fork back into the `securityonion` _dev_ branch.

#### Requirements

The following requirements must be satisfied in order for analyzer pull requests to be accepted into the Security Onion GitHub project:

- Analyzer contributions must not contain licensed dependencies or source code that is incompatible with the [GPLv2 licensing](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).
- All source code must pass the `flake8` lint check. This ensures source code conforms to the same style guides as the other analyzers. The Security Onion project will automatically run the linter after each push to a `securityonion` repository fork, and again when submitting a pull request. Failed lint checks will result in the submitter being sent an automated email message.
- All source code must include accompanying unit test coverage. The Security Onion project will automatically run the unit tests after each push to a `securityonion` repository fork, and again when submitting a pull request. Failed unit tests, or insufficient unit test coverage, will result in the submitter being sent an automated email message.
- Documentation of the analyzer, its input requirements, conditions for operation, and other relevant information must be clearly written in an accompanying analyzer metadata file. This file is described in more detail earlier in this document.
- Source code must be well-written and be free of security defects that can put users or their data at unnecessary risk.


