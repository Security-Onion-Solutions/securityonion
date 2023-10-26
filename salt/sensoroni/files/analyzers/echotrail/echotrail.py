import json
import os
import sys
import requests
import helpers
import argparse



# def testHash(hashVar):
#     # alternate response urls. choose one
#     #url = "https://api.echotrail.io/score/" + hashVar
#     url = "https://api.echotrail.io/insights/" + hashVar
#     header = {"x-api-key": "I7TXsJcq6p2TVwxnsFKcO5rflwLlhjewarRkUPq7"}
#     response = requests.request('GET', url=url, headers=header)
#     return response.json()

# pprint(testHash("438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7"))

def analyze(conf, input):
    checkConfigRequirements(conf)
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data['artifactType'])
    response = sendReq(conf, data['value'])
    return prepareResults(response)

def checkConfigRequirements(conf):
    if "api_key" not in conf or len(conf['api_key']) == 0:
        sys.exit(126)
    else:
        return True
    
def sendReq(conf, observ_value):
    url = conf['base_url'] + observ_value
    headers = {'x-api-key': conf['api_key']}
    #headers = {'x-api-key': 'I7TXsJcq6p2TVwxnsFKcO5rflwLlhjewarRkUPq7'}
    response = requests.request('GET', url=url, headers=headers)
    return response.json()

def prepareResults(raw):
    # checking for the 'filenames' key alone does
    # not work when querying by filename.
    # So, we can account for a hash query, a filename query,
    # and anything else with these if statements.
    if 'filenames' in raw.keys():
        summary = raw['filenames'][0][0]
    elif 'tags' in raw.keys():
        summary = raw['tags'][0][0]
    else:
        summary = 'inconclusive'
    status = 'info'
    return {'response':raw, 'summary':summary,'status':status}

def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description='Search Echotrail for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c','--config', metavar = 'CONFIG_FILE', default=dir + '/echotrail.yaml', help='optional config file to use instead of the default config file')
    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))
        #print(results)

if __name__ == '__main__':
    main()