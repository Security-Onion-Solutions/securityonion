from datetime import datetime, timedelta
import argparse
import requests
import helpers
import urllib3
import json
import sys
import os


# default usage is:
# python3 elasticsearch.py '{"artifactType":"hash", "value":"*"}'

# To use outside of a Security Onion box, pass in '-c test.yaml' at the end
# of the above command to give this analyzer some test values. You may edit the
# values in the test.yaml file freely.


def checkConfigRequirements(conf):
    # if the user hasn't given valid configurables, quit.
    if not conf['numResults']:
        sys.exit(126)
    if not conf['timeDeltaMinutes']:
        sys.exit(126)
    if (not conf['authUser'] or not conf['authPWD']) and not conf['api_key']:
        sys.exit(126)
    if not conf['index']:
        sys.exit(126)
    if not conf['base_url']:
        sys.exit(126)
    if not conf['timestampFieldName']:
        sys.exit(126)
    else:
        return True


def buildReq(conf, input):
    numberOfResults = conf['numResults']

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
            "bool": {
                "must": [{
                    "wildcard": {
                        type: input['value'],
                    },
                }
                ],
                "filter": {
                    "range": {
                        conf['timestampFieldName']: {
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
    uname = conf['authUser']
    pwd = conf['authPWD']
    apikey = conf['api_key']

    # Change before release!
    urllib3.disable_warnings()
    # With verify=False in the post request, we are disabling TLS authentification.
    # disable_warnings() simply suppresses these errors so Security Onion can
    # read the output properly.

    # The final version will have the verify parameter link to a .pem certificate
    # that will be configurable by the end user
    # if len(pwd) != 0 and len(uname) != 0:
    #     response = requests.post(str(url), auth=(
    #         uname, pwd), verify=False, data=query, headers=headers)
    # elif len(apikey) != 0:
    #     response = requests.post(str(url), auth=(
    #         apikey), verify=False, data=query, headers=headers)
    
    response = requests.post(str(url), auth=(
        uname, pwd), verify=False, data=query, headers=headers)
    return response.json()


def prepareResults(raw):
    # will report the *limited* amount of hits in the summary, not the true amount
    summary = f"Documents returned: {len(raw['hits']['hits'])}"
    status = 'info'
    return {'response': raw, 'summary': summary, 'status': status}


def analyze(conf, input):
    checkConfigRequirements(conf)
    data = json.loads(input)
    query = buildReq(conf, data)
    response = sendReq(conf, query)
    return prepareResults(response)


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(
        description='Search Elastic Search for a given artifact?')
    parser.add_argument('artifact', help='required artifact')
    parser.add_argument('-c', '--config', metavar='CONFIG_FILE', default=dir + '/elasticsearch.yaml',
                        help='optional config file to use instead of the default config file')
    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == '__main__':
    main()
