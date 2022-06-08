import json
import os
import sys
import requests
import helpers
import argparse


def checkConfigRequirements(conf):
    if "api_key" not in conf or len(conf['api_key']) == 0:
        sys.exit(126)
    else:
        return True


def sendReq(conf, meta, ip):
    url = conf['base_url']
    if conf['api_version'] == 'community':
        url = url + 'v3/community/' + ip
    elif conf['api_version'] == 'investigate' or 'automate':
        url = url + 'v2/noise/context/' + ip
    headers = {"key": conf['api_key']}
    response = requests.request('GET', url=url, headers=headers)
    return response.json()


def prepareResults(raw):
    if "message" in raw:
        if "Success" in raw["message"]:
            if "classification" in raw:
                if "benign" in raw['classification']:
                    status = "ok"
                    summary = "harmless"
                elif "malicious" in raw['classification']:
                    status = "threat"
                    summary = "malicious"
                elif "unknown" in raw['classification']:
                    status = "caution"
                    summary = "suspicious"
        elif "IP not observed scanning the internet or contained in RIOT data set." in raw["message"]:
            status = "ok"
            summary = "no_results"
        elif "Request is not a valid routable IPv4 address" in raw["message"]:
            status = "caution"
            summary = "invalid_input"
        else:
            status = "info"
            summary = raw["message"]
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
    parser = argparse.ArgumentParser(description='Search Greynoise for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar="CONFIG_FILE", default=dir + "/greynoise.yaml", help='optional config file to use instead of the default config file')

    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
