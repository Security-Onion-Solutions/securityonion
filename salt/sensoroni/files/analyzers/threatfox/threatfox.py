import requests
import argparse
import json
from pprint import pprint
#import helpers

# API keys (probably unnecessary)
# da3f0475d11eee92eee0d0a7de0665a6
# 3cebe3c26ae869e91f094ff99e57428c

def testHashQuery(hash):
        response = requests.post('https://threatfox-api.abuse.ch/api/v1/', json.dumps({"query":"search_hash", "hash":hash}))
        print(response.json())
        return response.json()

def testIPQuery(ip):
        response = requests.post('https://threatfox-api.abuse.ch/api/v1/', json.dumps({"query":"search_ioc", "search_term":ip}));
        pprint(response.json())
        return response.json()


def prepareResults(raw):
        if raw['data'][0]['threat_type_desc'] != '' :
                summary = raw['data'][0]['threat_type_desc']
        else:
                summary = raw['data'][0]['threat_type']
                
        if raw['data'][0]['confidence_level'] > 75:
                status = 'threat'
        elif raw['data'][0]['confidence_level'] > 50:
                status = 'caution'
        elif raw['data'][0]['confidence_level'] > 25:
                status = 'info'
        else:
                status = 'ok'
        #look into json.deseralized
        #summary threattype, threattype desc
        #use confidence level to determine malware threat?
        results = {'response': raw, 'summary': summary, 'status': status }
        pprint(results)
        return json.dumps(results)


print("------------------------------------------------------------------------")
prepareResults(testHashQuery('2151c4b970eff0071948dbbc19066aa4'))
print("------------------------------------------------------------------------")
#testIPQuery("139.180.203.104")

#Questions
#Do we need submission for (API KEY)?
#What data would you like to see from the JSON output?

