from datetime import datetime, timedelta
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
    elif "authUser" not in conf or len(conf['authUser']) == 0:
        sys.exit(126)
    elif "authPWD" not in conf or len(conf['authPWD']) == 0:
        sys.exit(126)
    #add the rest
    else:
        return True


def buildReq(conf, input, numberOfResults = 10):
    mappings = conf['map']
    cur_time = datetime.now()
    start_time = cur_time - timedelta(minutes=conf['timeDeltaMinutes'])
    print(cur_time.strftime('%Y-%m-%dT%H:%M:%S'))
    print(start_time.strftime('%Y-%m-%dT%H:%M:%S'))

    if(input['artifactType'] in mappings):
    # query that looks for specified observable type in every document/index
        query = {
            "from": 0,
            "size": numberOfResults,
            "query": {
                "bool":{
                    "must":[{
                            "wildcard": {
                                mappings[input['artifactType']]: input['value'],
                            },
                        }
                    ],
                    "filter":{
                        "range":{
                            conf['timestampFieldName']:{
                                "gte": start_time.strftime('%Y-%m-%dT%H:%M:%S'),
                                "lte": cur_time.strftime('%Y-%m-%dT%H:%M:%S')
                            }
                        }
                    }
                }
            }
        }
    else:
    # for all document output
    # issue is we may need to protect against _all index, and make sure this query 
    # does not provide back the original query statement (i could have messed up on this part)
    # does return all the documents back
        query = {
            "from": 0,
            "size": numberOfResults,
            "query": {
                "match_all": {
                
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
    return response.json()


def prepareResults(raw, observableType, conciseOutput = False):
    # will report the *limited* amount of hits in the summary, not the true amount
    summary = f"Documents returned: {len(raw['hits']['hits'])}"
    status = 'info'

    # if raw['hits']['hits'] and conciseOutput:
    #     organized_hits = []
    #     hits = raw['hits']['hits']
    #     for hit in hits:
    #         organized_hits.append(
    #             {'_id': hit['_id'], observableType: hit['_source'][observableType]})
    #     raw['hits']['hits'] = organized_hits
    
    return {'response': raw, 'summary': summary, 'status': status}


def analyze(conf, input):
    checkConfigRequirements(conf)
    data = json.loads(input)
    # query = buildReq(conf['map'], conf['numResults'])
    # REPLACE BELOW WITH ABOVE, SHOULD NOT BE HARDCODED
    query = buildReq(conf, data, 5)
    
    response = sendReq(conf['index'], query)
    return prepareResults(response, conf['map'])


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description='Search Elastic Search for a given artifact?')
    parser.add_argument('artifact', help='required artifact')
    parser.add_argument('-c', '--config', metavar='CONFIG_FILE', default=dir + '/elasticsearch.yaml',
                        help='optional config file to use instead of the default config file')
    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == '__main__':
    main()
