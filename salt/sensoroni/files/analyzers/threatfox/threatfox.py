import requests
import helpers
import json
import sys
import argparse
import os


def buildReq(observ_type, observ_value):
    # supports hash, ip, and domain. determines which query type to send.
    if observ_type == 'hash':
        qterms = {'query': 'search_hash', 'hash': observ_value}
    elif observ_type == 'ip' or observ_type == 'domain':
        qterms = {'query': 'search_ioc', 'search_term': observ_value}
    return qterms


def checkConfigRequirements(conf):
    if not conf.get('api_key'):
        sys.exit(126)
    else:
        return True


def sendReq(conf, meta, query):
    # send a post request based off of our compiled query
    url = meta['baseUrl']
    headers = {}
    if conf.get('api_key'):
        headers['Auth-Key'] = conf['api_key']
    response = requests.post(url, json.dumps(query), headers=headers)
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


def analyze(conf, input):
    # put all of our methods together, pass them input, and return
    # properly formatted json/python dict output
    checkConfigRequirements(conf)
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data["artifactType"])
    query = buildReq(data['artifactType'], data['value'])
    response = sendReq(conf, meta, query)
    return prepareResults(response)


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(
        description='Search ThreatFox for a given artifact')
    parser.add_argument(
        'artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar='CONFIG_FILE', default=dir + '/threatfox.yaml',
                        help='optional config file to use instead of the default config file')
    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == '__main__':
    main()
