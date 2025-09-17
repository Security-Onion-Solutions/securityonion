import json
import os
import requests
import sys
import helpers
import argparse


def checkConfigRequirements(conf):
    if not conf.get('api_key'):
        sys.exit(126)
    else:
        return True


def buildReq(artifact_value):
    return {"url": artifact_value}


def sendReq(conf, meta, payload):
    url = meta['baseUrl']
    headers = {}
    if conf.get('api_key'):
        headers['Auth-Key'] = conf['api_key']
    response = requests.request('POST', url, data=payload, headers=headers)
    return response.json()


def prepareResults(raw):
    if 'threat' in raw:
        summary = raw['threat']
        status = "threat"
    elif 'query_status' in raw:
        summary = raw['query_status']
        if summary == 'no_results':
            status = "ok"
        else:
            status = "caution"
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
    payload = buildReq(data["value"])
    response = sendReq(conf, meta, payload)
    return prepareResults(response)


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(
        description='Search URLhaus for a given artifact')
    parser.add_argument(
        'artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar='CONFIG_FILE', default=dir + '/urlhaus.yaml',
                        help='optional config file to use instead of the default config file')
    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
