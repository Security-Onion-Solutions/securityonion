import argparse
import yaml
import requests
import json
import os
from pprint import pprint
# pprint should (probably) not be present in the final version.


def buildReq(observ_type, observ_value):
        if observ_type == 'hash':
                qterms = {'query':'search_hash', 'hash':observ_value}
        elif observ_type == 'ip':
                qterms = {'query':'search_ioc', 'search_term':observ_value}
        elif observ_type == 'domain':
                qterms = {'query':'search_ioc', 'search_term':observ_value}
        else:
                return
        return qterms
        

def sendReq(meta, query):
        url = meta['base_url']
        response = requests.post(url, json.dumps(query))
        return response.json()


def prepareResults(raw):
        if raw['query_status'] == 'ok':
                # look into deserializing json since raw['data'][0] is a little scuffed
                parsed = raw['data'][0]
                
                if parsed['threat_type_desc'] != '' :
                        summary = parsed['threat_type_desc']
                else:
                        summary = parsed['threat_type']
                
                if parsed['confidence_level'] > 75:
                        status = 'threat'
                elif parsed['confidence_level'] > 50:
                        status = 'caution'
                elif parsed['confidence_level'] > 25:
                        status = 'info'
                else:
                        status = 'ok'
        elif raw['query_status'] in ['no_result', 'illegal_search_term', 'illegl_hash']:
                #raw = {}
                status = 'info'
                summary = 'no result'
        else:
                # ask about this in the meeting later
                raw = {}
                status = 'caution'
                summary = 'internal_failure'
        
        results = {'response': raw, 'summary': summary, 'status': status }
        return results


# dont delete could be used for unit testing

#prepareResults(buildReq('hash','2151c4b970eff0071948dbbc19066aa4')))
#prepareResults(buildReq('hash','2151c4b970eff0071948dbbc19066ab4'))
#prepareResults(buildReq('domain', 'http://google.com'))
#prepareResults(buildReq('domain', 'https://google.com'))
#prepareResults(buildReq('', '2151c4b970eff0071948dbbc19066aa4'))
#prepareResults(buildReq('hash', '2jkasdhfklasdjfh4'))
#prepareResults(buildReq('domain', 'a'))


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    print('found dir')
    parser = argparse.ArgumentParser(description='Query Threatfox for a suspect domain, hash, or IP')
    print('created parser')
    parser.add_argument('artifact', help='JSON with artifact type and value')
    parser.add_argument('-c', '--config', metavar='CONFIG_FILE', default=dir + '\\threatfox.yaml',
                        help='Parameter for the use of a custom config file in place of the default yaml')

    args = parser.parse_args()
    if args.artifact:
        data = json.loads(args.artifact)
        query = buildReq(data["artifactType"], data["value"])
        config = open(args.config)
        response = sendReq(yaml.safe_load(config), query)
        results = prepareResults(response)
        pprint(results)
        config.close()

if __name__ == '__main__':
        main()