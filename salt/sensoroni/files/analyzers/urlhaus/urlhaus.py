#!/usr/bin/python3
import json
import requests
import sys
import helpers


def buildReq(artifact_value):
    return {"url": artifact_value}


def sendReq(meta, payload):
    url = meta['baseUrl']
    response = requests.request('POST', url, data=payload)
    return response.json()


def prepareResults(raw):
    if 'threat' in raw:
        summary = raw['threat']
        status = "danger"
    elif 'query_status' in raw:
        summary = raw['query_status']
        if summary == 'no_results':
            status = "ok"
        else:
            status = "error"
    results = {'response': raw, 'summary': summary, 'status': status}
    return results


def analyze(input):
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data["artifactType"])
    payload = buildReq(data["value"])
    response = sendReq(meta, payload)
    return prepareResults(response)


def main():
    results = analyze(sys.argv[1])
    print(json.dumps(results))


if __name__ == "__main__":
    main()
