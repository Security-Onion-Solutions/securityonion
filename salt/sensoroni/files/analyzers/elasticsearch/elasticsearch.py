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
    if len(conf['base_url']) == 0:
        sys.exit(126)
    else:
        return True


def buildReq(conf, input):
    if conf['numResults'] in conf:
        numberOfResults = conf['numResults']
    else:
        numberOfResults = 10
    
    if conf['map'] != None:  
        mappings = conf['map']
    else:
        mappings = dict()
        
    cur_time = datetime.now()
    start_time = cur_time - timedelta(minutes=int(conf['timeDeltaMinutes']))

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


def sendReq(conf, query):
    headers = {
        'Content-Type': 'application/json',
    }
    
    url = conf['base_url'] + conf['index'] + '/_search'
    authUser = conf['authUser']
    authPWD = conf['authPWD']
    # code below is hard-coded for testing outside of SO
    # url = "https://192.168.56.106:9200/" + conf['index'] + "/_search"
    # authUser = "elastic"
    # authPWD = "adminadmin"
    
    response = requests.post(url, auth=(
        authUser, authPWD), verify=False, data=query, headers=headers)
    return response.json()


def prepareResults(raw, conciseOutput = False):
    # will report the *limited* amount of hits in the summary, not the true amount
    summary = f"Documents returned: {len(raw['hits']['hits'])}"
    status = 'info'
    
    return {'response': raw, 'summary': summary, 'status': status}


def analyze(conf, input):
    #checkConfigRequirements(conf)
    # the above may possibly cause the analyzer to stop prematurely
    data = json.loads(input)
    query = buildReq(conf, data)
    response = sendReq(conf, query)
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
