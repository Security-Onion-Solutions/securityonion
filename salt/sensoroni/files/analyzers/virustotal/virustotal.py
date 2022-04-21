import json
import requests
import argparse
import helpers
import os
import sys


def checkConfigRequirements(conf):
    if "api_key" not in conf or len(conf['api_key']) == 0:
        sys.exit(126)
    else:
        return True


def buildHeaders(conf):
    headers = {"x-apikey": conf["api_key"]}
    return headers


def sendReq(conf, meta, payload, headers):
    url = conf['base_url']
    response = requests.request('GET', url + payload, headers=headers)
    return response.json()


def prepareResults(raw):
    malicious = 0
    harmless = 0
    undetected = 0
    suspicious = 0
    timeout = 0

    if "data" in raw:
        entries = raw["data"]
        for data in entries:
            if "attributes" in data:
                attrs = data["attributes"]
                if "last_analysis_stats" in attrs:
                    stats = attrs["last_analysis_stats"]
                    if len(stats) > 0:
                        suspicious += stats["suspicious"]
                        malicious += stats["malicious"]
                        harmless += stats["harmless"]
                        undetected += stats["undetected"]
                        timeout += stats["timeout"]

    if malicious > 0:
        summary = "malicious"
        status = "threat"
    elif suspicious > 0:
        summary = "suspicious"
        status = "caution"
    elif timeout > 0:
        summary = "timeout"
        status = "caution"
    elif harmless > 0 or undetected > 0:
        summary = "harmless"
        status = "ok"
    else:
        summary = "internal_failure"
        status = "caution"

    results = {'response': raw, 'summary': summary, 'status': status}
    return results


def analyze(conf, input):
    checkConfigRequirements(conf)
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data["artifactType"])
    headers = buildHeaders(conf)
    response = sendReq(conf, meta, data["value"], headers)
    return prepareResults(response)


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description='Search VirusTotal for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar="CONFIG_FILE", default=dir + "/virustotal.yaml", help='optional config file to use instead of the default config file')

    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
