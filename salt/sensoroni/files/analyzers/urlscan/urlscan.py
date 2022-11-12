import json
import requests
import helpers
import sys
import os
import argparse
import time


def checkConfigRequirements(conf):
    if "enabled" in conf:
        if "api_key" not in conf or len(conf['api_key']) == 0:
            sys.exit(126)
        else:
            return True
    else:
        sys.exit(126)


def buildReq(conf, artifact_type, artifact_value):
    headers = {"API-Key": conf["api_key"]}
    url = conf['base_url'] + 'scan/'
    visibility = conf['visibility']
    data = {"url": artifact_value, "visibility": visibility}
    return url, headers, data


def getReport(conf, report_url):
    report = requests.request('GET', report_url)
    timeout = conf.get('timeout', 300)
    counter = 0
    while report.status_code == 404:
        time.sleep(2)
        counter += 2
        if counter >= timeout:
            break
        report = requests.request('GET', report_url)
    return report


def sendReq(url, headers, data):
    submission = requests.request('POST', url=url, headers=headers, data=data).json()
    report_url = submission['api']
    return report_url


def prepareResults(raw):
    if raw and "verdicts" in raw:
        if raw["verdicts"]["overall"]["malicious"] is True:
            status = "threat"
            summary = "malicious"
        elif raw["verdicts"]["overall"]["score"] > 0:
            status = "caution"
            summary = "suspicious"
        else:
            status = "info"
            summary = "analysis_complete"
    else:
        status = "caution"
        summary = "internal_failure"

    results = {'response': raw, 'status': status, 'summary': summary}
    return results


def analyze(conf, input):
    checkConfigRequirements(conf)
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data["artifactType"])
    request = buildReq(conf, data["artifactType"], data["value"])
    report_url = sendReq(request[0], request[1], request[2])
    time.sleep(10)
    report = getReport(conf, report_url)
    return prepareResults(report.json())


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description='Search urlscan for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar="CONFIG_FILE", default=dir + "/urlscan.yaml", help='optional config file to use instead of the default config file')

    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
