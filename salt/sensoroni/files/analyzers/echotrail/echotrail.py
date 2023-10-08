import json
import os
import sys
import requests
import helpers
import argparse
from pprint import pprint


# def testHash(hashVar):        
#     url = "https://api.echotrail.io/insights/" + hashVar
#     header = {"x-api-key": "I7TXsJcq6p2TVwxnsFKcO5rflwLlhjewarRkUPq7"}
#     response = requests.request('GET', url=url, headers=header)   
#     return response.json()

# pprint(testHash("438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7"))

def analyze(conf, input):
    checkConfigRequirements(conf)
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta,data['artifactType'])
    response = sendReq(conf, meta, data['value'])
    return prepareResults(response)

def checkConfigRequirements(conf):
    if "api_key" not in conf:
        sys.exit(126)
    else:
        return True
    
def sendReq(conf, meta, observ_value):        
    url = conf['base_url'] + observ_value
    #need to account for pro version?
    headers = {'x-api-key': conf['api_key']}
    response = requests.request('GET', url=url, headers=headers)
    return response.json()

def prepareResults(raw):
    summary = raw['filenames'][0][0]
    status = 1
    results = {'response':raw, 'summary':summary,'status':status}

def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description='Search Echotrail for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c','--config', metavar = 'CONFIG_FILE', default=dir + '/echotrail.yaml', help='optional config file to use instead of the default config file')
    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))

if __name__ == '__main__':
    main()