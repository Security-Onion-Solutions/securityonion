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


def buildReq(conf, artifactType, artifactValue):
    indicatorTypes = ["domain", "hash", "ip", "url"]
    if artifactType in indicatorTypes:
        url = conf['base_url'] + '/info.php'
        params = {"key": conf["api_key"], "indicator": artifactValue}
    else:
        if artifactType == "uri_path":
            query = "http.location=" + artifactValue
            url = conf['base_url'] + '/explore.php'
        elif artifactType == "user-agent":
            query = "http.useragent_normaliser=" + artifactValue
            url = conf['base_url'] + '/explore.php'
        params = {"key": conf["api_key"], "q": query, "limit": 100}

    return url, params


def sendReq(url, params):
    response = requests.request('GET', url, params=params)
    return response.json()


def prepareResults(raw):
    classified = []
    classification = {
                "high": "malicious",
                "medium": "suspicious",
                "low": "harmless",
                "none": "none",
                "unknown": "unknown"
            }

    if raw:
        if 'results' in raw:
            if raw['results'] == []:
                classified.append("no_results")
            else:
                for r in raw['results']:
                    risk = r['risk']
                    classified.append(classification.get(risk))
        elif "risk" in raw:
            classified.append(classification.get(raw['risk']))
        elif "error" in raw and raw["error"] == "Indicator not found.":
            classified.append("no_results")
    if classified.count('malicious') > 0:
        summary = "malicious"
        status = "threat"
    elif classified.count('suspicious') > 0:
        summary = "suspicious"
        status = "caution"
    elif classified.count('harmless') or classified.count('none') > 0:
        summary = "harmless"
        status = "ok"
    elif classified.count('unknown') > 0:
        summary = ""
        status = "unknown"
    elif classified.count('no_results') > 0:
        summary = "no_results"
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
    request = buildReq(conf, data["artifactType"], data["value"])
    response = sendReq(request[0], request[1])
    return prepareResults(response)


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description='Search Pulsedive for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar="CONFIG_FILE", default=dir + "/pulsedive.yaml", help='optional config file to use instead of the default config file')

    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
