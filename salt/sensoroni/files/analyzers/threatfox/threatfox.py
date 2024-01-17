import requests
import helpers
import json
import sys


def buildReq(observ_type, observ_value):
    # supports hash, ip, and domain. determines which query type to send.
    if observ_type == 'hash':
        qterms = {'query': 'search_hash', 'hash': observ_value}
    elif observ_type == 'ip' or observ_type == 'domain':
        qterms = {'query': 'search_ioc', 'search_term': observ_value}
    return qterms


def sendReq(meta, query):
    # send a post request based off of our compiled query
    url = meta['baseUrl']
    response = requests.post(url, json.dumps(query))
    return response.json()


def prepareResults(raw):
    # gauge threat level based off of threatfox's confidence level
    if raw != {} and raw['query_status'] == 'ok':
        parsed = raw['data'][0]

        # get summary
        if parsed['threat_type'] != '':
            summary = parsed['threat_type']
        else:
            summary = parsed['threat_type_desc']

        if parsed['confidence_level'] > 75:
            status = 'threat'
        elif parsed['confidence_level'] > 50:
            status = 'caution'
        elif parsed['confidence_level'] > 25:
            status = 'info'
        else:
            status = 'ok'
    elif raw != {} and raw['query_status'] in ['no_result', 'illegal_search_term', 'illegl_hash']:
        status = 'info'
        summary = 'no result'
    else:
        raw = {}
        status = 'caution'
        summary = 'internal_failure'

    results = {'response': raw, 'summary': summary, 'status': status}
    return results


def analyze(input):
    # put all of our methods together, pass them input, and return
    # properly formatted json/python dict output
    data = json.loads(input)
    meta = helpers.loadMetadata(__file__)
    helpers.checkSupportedType(meta, data["artifactType"])
    query = buildReq(data['artifactType'], data['value'])
    response = sendReq(meta, query)
    return prepareResults(response)


def main():
    if len(sys.argv) == 2:
        results = analyze(sys.argv[1])
        print(json.dumps(results))
    else:
        print("ERROR: Input is not in proper JSON format")


if __name__ == '__main__':
    main()
