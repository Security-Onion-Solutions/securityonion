import json
import requests
import helpers
import sys
import os
import argparse


def buildReq(conf, artifact_type, artifact_value):
    headers = {"X-OTX-API-KEY": conf["api_key"]}
    base_url = conf['base_url']
    if artifact_type == "ip":
        uri = "indicators/IPv4/"
    elif artifact_type == "url":
        uri = "indicators/url/"
    elif artifact_type == "domain":
        uri = "indicators/domain/"
    elif artifact_type == "hash":
        uri = "indicators/file/"
    section = "/general"
    url = base_url + uri + artifact_value + section
    return url, headers


def checkConfigRequirements(conf):
    if "api_key" not in conf or len(conf['api_key']) == 0:
        sys.exit(126)
    else:
        return True


def sendReq(url, headers):
    response = requests.request('GET', url, headers=headers)
    return response.json()


def prepareResults(response):
    if len(response) != 0:
        raw = response
        if 'reputation' in raw:
            reputation = raw["reputation"]
            if reputation == 0:
                status = "ok"
                summaryinfo = "harmless"
            elif reputation > 0 and reputation < 50:
                status = "ok"
                summaryinfo = "likely_harmless"
            elif reputation >= 50 and reputation < 75:
                status = "caution"
                summaryinfo = "suspicious"
            elif reputation >= 75 and reputation <= 100:
                status = "threat"
                summaryinfo = "malicious"
        else:
            status = "info"
            summaryinfo = "analyzer_analysis_complete"
    else:
        raw = {}
        status = "caution"
        summaryinfo = "internal_failure"
    results = {'response': raw, 'status': status, 'summary': summaryinfo}
    return results


def analyze(conf, input):
    checkConfigRequirements(conf)
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data["artifactType"])
    request = buildReq(conf, data["artifactType"], data["value"])
    response = sendReq(request[0], request[1])
    return prepareResults(response)


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description='Search Alienvault OTX for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar="CONFIG_FILE", default=dir + "/otx.yaml", help='optional config file to use instead of the default config file')

    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
