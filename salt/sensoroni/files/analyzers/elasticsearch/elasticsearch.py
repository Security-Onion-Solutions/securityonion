from datetime import datetime, timedelta
import argparse
import helpers
import requests
import json
import sys
import os



# default usage is:
# python3 elasticsearch.py '{"artifactType":"hash", "value":"*"}'
# ^ the above queries documents with field 'hash' with any value

def checkConfigRequirements(conf):
    # if the user hasn't given a valid elasticsearch domain, exit gracefully
    if "base_url" not in conf or len(conf['base_url']) == 0:
        sys.exit(126)
    #add the rest
    else:
        return True


def buildReq(conf, input):
    if conf['numResults'] in conf:
        numberOfResults = conf['numResults']
    else:
        numberOfResults = 10
        
    mappings = conf['map']
    cur_time = datetime.now()
    start_time = cur_time - timedelta(minutes=conf['timeDeltaMinutes'])

    if input['artifactType'] in mappings:
        type = mappings[input['artifactType']]
    else:
        type = input['artifactType']
        
    query = {
        "from": 0,
        "size": numberOfResults,
        "query": {
            "bool":{
                "must":[{
                        "wildcard": {
                            type : input['value'],
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

    return json.dumps(query)


def sendReq(index, query):
    headers = {
        'Content-Type': 'application/json',
    }
    
    # url = meta['domain'] + index + '_search'
    # authUser = meta['authUser']
    # authPWD = meta['authPWD']
    # REPLACE BELOW WITH ABOVE, SHOULD NOT BE HARDCODED
    url = "https://192.168.56.106:9200/" + index + "/_search"
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
    query = buildReq(conf, data)
    # REPLACE BELOW WITH ABOVE, SHOULD NOT BE HARDCODED
    # query = buildReq(conf, data, 5)
    
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
