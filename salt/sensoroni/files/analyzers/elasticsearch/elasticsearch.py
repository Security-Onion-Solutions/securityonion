from datetime import datetime, timedelta
import argparse
import requests
import helpers
import json
import sys
import os

# As it stands, this analyzer does not support querying for mixed-case fields without disregarding case completely.
# So the current version will only support querying for all-lowercase alphanumerical values.

# default usage is:
# python3 elasticsearch.py '{"artifactType":"hash", "value":"*"}'

# To use outside of a Security Onion box, pass in '-c test.yaml' at the end
# of the above command to give this analyzer some test values. You may edit the
# values in the test.yaml file freely.


def checkConfigRequirements(conf):
    # if the user hasn't given valid configurables, quit.
    if not conf['num_results']:
        sys.exit(126)
    if not conf['time_delta_minutes']:
        sys.exit(126)
    if (not conf['auth_user'] or not conf['auth_pwd']) and not conf['api_key']:
        sys.exit(126)
    if not conf['index']:
        sys.exit(126)
    if not conf['base_url']:
        sys.exit(126)
    if not conf['timestamp_field_name']:
        sys.exit(126)
    if not conf['cert_path']:
        sys.exit(126)
    return True


def buildReq(conf, input):
    # structure a query to send to the Elasticsearch machine
    # based off of user configurable values
    num_results = conf['num_results']

    if conf['map'] is not None:
        mappings = conf['map']
    else:
        mappings = dict()

    cur_time = datetime.now()
    start_time = cur_time - timedelta(minutes=int(conf['time_delta_minutes']))

    if input['artifactType'] in mappings:
        type = mappings[input['artifactType']]
    else:
        type = input['artifactType']

    query = {
        "from": 0,
        "size": num_results,
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
                        conf['timestamp_field_name']: {
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
    # send configured query with even more user specification
    headers = {}
    url = conf['base_url'] + conf['index'] + '/_search'
    uname = conf['auth_user']
    pwd = conf['auth_pwd']
    apikey = conf['api_key']
    cert_path = conf['cert_path']

    if pwd and uname:
        headers = {
            'Content-Type': 'application/json',
        }
        response = requests.post(str(url), auth=(
            uname, pwd), verify=cert_path, data=query, headers=headers)
    elif apikey:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Apikey {apikey}"
        }
        response = requests.post(
            str(url), verify=cert_path, data=query, headers=headers)

    return response.json()


def prepareResults(raw):
    # returns raw API response, amount of hits found, and status of request in order
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
        description='Search Elasticsearch for a given artifact?')
    parser.add_argument('artifact', help='required artifact')
    parser.add_argument('-c', '--config', metavar='CONFIG_FILE', default=dir + '/elasticsearch.yaml',
                        help='optional config file to use instead of the default config file')
    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == '__main__':
    main()
