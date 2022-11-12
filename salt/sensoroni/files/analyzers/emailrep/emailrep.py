import json
import os
import sys
import requests
import helpers
import argparse


def checkConfigRequirements(conf):
    if "api_key" not in conf:
        sys.exit(126)
    else:
        return True


def sendReq(conf, meta, email):
    url = conf['base_url'] + email
    headers = {"Key": conf['api_key']}
    response = requests.request('GET', url=url, headers=headers)
    return response.json()


def prepareResults(raw):
    if "suspicious" in raw:
        if raw['suspicious'] is True:
            status = "caution"
            summary = "suspicious"
        elif raw['suspicious'] is False:
            status = "ok"
            summary = "harmless"
    elif "status" in raw:
        if raw["reason"] == "invalid email":
            status = "caution"
            summary = "invalid_input"
        if "exceeded daily limit" in raw["reason"]:
            status = "caution"
            summary = "excessive_usage"
    else:
        status = "caution"
        summary = "internal_failure"
    results = {'response': raw, 'summary': summary, 'status': status}
    return results


def analyze(conf, input):
    checkConfigRequirements(conf)
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data["artifactType"])
    response = sendReq(conf, meta, data["value"])
    return prepareResults(response)


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description='Search EmailRep for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar="CONFIG_FILE", default=dir + "/emailrep.yaml", help='optional config file to use instead of the default config file')

    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
