import argparse
import helpers
import requests
import json
import sys
import os


def checkConfigRequirements(conf):
    # if the user hasn't given a valid elasticsearch domain, exit gracefully
    if "domain" not in conf or len(conf['domain']) == 0:
        sys.exit(126)
    else:
        return True


def buildReq(observableType, numberOfResults):
    # query that looks for specified observable type in every document/index
    query = {
        "from": 0,
        "size": numberOfResults,
        "query": {
            "wildcard": {
                observableType: "*"
            }
        }
    }
    return json.dumps(query)


def sendReq(index, query):
    headers = {
        'Content-Type': 'application/json',
    }
    
    # url = meta['domain'] + index + '_search'
    # authUser = meta['authUser']
    # authPWD = meta['authPWD']
    # REPLACE BELOW WITH ABOVE, SHOULD NOT BE HARDCODED
    url = "https://192.168.56.106:9200/" + index + '_search'
    authUser = "elastic"
    authPWD = "adminadmin"
    
    response = requests.post(url, auth=(
        authUser, authPWD), verify=False, data=query, headers=headers)
    print(response.json())
    return response.json()


def prepareResults(raw, observableType):
    # will report the *limited* amount of hits in the summary, not the true amount
    summary = f"{len(raw['hits']['hits'])} hits recorded."
    status = 'info'

    # because each search hit in ES will return a lot of unrelated information,
    # we grab the related info and snip the rest.
    if raw['hits']['hits']:
        organized_hits = []
        hits = raw['hits']['hits']
        for hit in hits:
            organized_hits.append(
                {'_id': hit['_id'], observableType: hit['_source'][observableType]})

    raw['hits']['hits'] = organized_hits
    return {'response': raw, 'summary': summary, 'status': status}


def analyze(conf):
    checkConfigRequirements(conf)
    
    # query = buildReq(conf['observable_type'], conf['numResults'])
    # REPLACE BELOW WITH ABOVE, SHOULD NOT BE HARDCODED
    query = buildReq(conf['observable_type'], 5)
    
    response = sendReq(conf['index'], query)
    return prepareResults(response, conf['observable_type'])


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(
        description='Search Elastic Search for a given artifact?')
    parser.add_argument('-c', '--config', metavar='CONFIG_FILE', default=dir + '/elasticsearch.yaml',
                        help='optional config file to use instead of the default config file')
    args = parser.parse_args()
    results = analyze(helpers.loadConfig(args.config))
    print(json.dumps(results))


if __name__ == '__main__':
    main()
