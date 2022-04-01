#!/usr/bin/python3
import json
import requests
import sys
import helpers


def buildReq(meta, artifact_value):
    base_url = meta['baseUrl']
    url = base_url
    payload = {"url": artifact_value}
    return payload, url


def sendReq(meta, payload, url):
    response = requests.request('POST', url, data=payload)
    raw = response.json()
    if raw['query_status'] == "no_results":
        summaryinfo = "No results available."
    elif raw['query_status'] == "invalid_url":
        summaryinfo = "Invalid URL."
    if 'threat' in raw:
        threat = raw['threat']
        if threat == 'malware_download':
            summaryinfo = "Threat: Malware"
        else:
            summaryinfo = threat
    summary = summaryinfo
    results = {'response': raw, 'summary': summary}
    print(json.dumps(results))


def main():
    meta = helpers.loadMeta(__file__)
    data = helpers.loadData(sys.argv[1])
    helpers.checkSupportedType(meta, data[0])
    request = buildReq(meta, data[1])
    payload = request[0]
    url = request[1]
    sendReq(meta, payload, url)


if __name__ == "__main__":
    main()
