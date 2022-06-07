import json
import os
import requests
import helpers
import argparse


def sendReq(conf, meta, hash):
    url = conf['base_url'] + hash
    response = requests.request('GET', url)
    return response.json()


def prepareResults(raw):
    if "error" in raw:
        if "Sorry" in raw["error"]:
            status = "ok"
            summary = "no_results"
        elif "Invalid hash" in raw["error"]:
            status = "caution"
            summary = "invalid_input"
        else:
            status = "caution"
            summary = "internal_failure"
    else:
        status = "info"
        summary = "suspicious"
    results = {'response': raw, 'summary': summary, 'status': status}
    return results


def analyze(conf, input):
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data["artifactType"])
    response = sendReq(conf, meta, data["value"])
    return prepareResults(response)


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description='Search JA3er for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar="CONFIG_FILE", default=dir + "/ja3er.yaml", help='optional config file to use instead of the default config file')

    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
