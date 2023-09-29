import requests
import helpers
import json
import os
import sys



def buildReq(observ_type, observ_value):
    

    if observ_type == 'hash':
        qterms = {'query': 'search_hash', 'hash': observ_value}
    elif observ_type == 'ip':
        qterms = {'query': 'search_ioc', 'search_term': observ_value}
    elif observ_type == 'domain':
        qterms = {'query': 'search_ioc', 'search_term': observ_value}
    else:
        return
    return qterms


def sendReq(meta, query):
   

    url = meta['baseUrl']
    response = requests.post(url, json.dumps(query))
    return response.json()


def prepareResults(raw):
    #need to fix for raw = {} in unit test also
    if raw['query_status'] == 'ok':
        
        parsed = raw['data'][0]

        if parsed['threat_type_desc'] != '':
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

   
    elif raw != {} and raw['query_status'] in ['no_result', 'illegal_search_term', 'illegl_hash']:
       
        status = 'info'
        summary = 'no result'
    else:
        
        #raw = {}
        status = 'caution'
        summary = 'internal_failure'

    results = {'response': raw, 'summary': summary, 'status': status}
    return results


def analyze(input):
    
    data = json.loads(input)
    meta = helpers.loadMetadata(__file__)
       
    
    query = buildReq(data['artifactType'], data['value'])
    response = sendReq(meta, query)
    return prepareResults(response)


def main():
    if len(sys.argv) == 2:
        results = analyze(sys.argv[1])
        print(json.dumps(results))
    else:
        print("ERROR: Input is not in proper JSON format")


if __name__ == '__main__':
    main()


