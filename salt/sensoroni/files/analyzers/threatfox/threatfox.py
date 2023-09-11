# URLS SHOULD NOT BE HARD-CODED
# !!! IMPORTANT !!!

import requests
import argparse
import json
from pprint import pprint
#import helpers


# API keys (probably unnecessary)
# da3f0475d11eee92eee0d0a7de0665a6
# 3cebe3c26ae869e91f094ff99e57428c


# def HashQuery(hash):        
#         response = requests.post('https://threatfox-api.abuse.ch/api/v1/', json.dumps({'query':'search_hash', 'hash':hash}))
#         #pprint(response.json())
#         if response.status_code != 200:
#                 return {}
#         return response.json()


# def IPDomainQuery(value):
#         response = requests.post('https://threatfox-api.abuse.ch/api/v1/', json.dumps({'query':'search_ioc', 'search_term':value}))
#         #pprint(response.json())
#         if response.status_code != 200:
#                 return {}
#         return response.json()


def buildReq(observ_type, observ_value):
        base_url = 'https://threatfox-api.abuse.ch/api/v1/'
        qterms = {}
        #check the length and correct ip or domain?
        if observ_type == "hash":
                qterms = {'query':'search_hash', 'hash':observ_value}
        elif observ_type == "ip":
                qterms = {'query':'search_ioc', 'search_term':observ_value}
        elif observ_type == "domain":
                qterms = {'query':'search_ioc', 'search_term':observ_value}
        else:
                return {}
        
        response = requests.post(base_url, json.dumps(qterms))
        
        if response.status_code != 200:
                return {}
        pprint(response.json())
        return response.json()


def prepareResults(raw):
        if  raw != {} and raw['query_status'] == 'ok':
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
        elif raw != {} and raw['query_status'] == 'no_result':
                raw = {}
                status = 'info'
                summary = 'no result'
        else:
                #ask about this in the meeting later
                raw = {}
                status = 'caution'
                summary = 'internal_failure'
                
                
        #look into json.deseralized
        #summary threattype, threattype desc
        #use confidence level to determine malware threat?
        
        results = {'response': raw, 'summary': summary, 'status': status }
        pprint(results)
        return json.dumps(results)


#dont delete could be used for unit testing

#prepareResults(buildReq('hash','2151c4b970eff0071948dbbc19066aa4'))
#prepareResults(buildReq('hash','2151c4b970eff0071948dbbc19066ab4'))
#prepareResults(buildReq('domain', 'http://google.com'))
#prepareResults(buildReq('domain', 'https://google.com'))
#prepareResults(buildReq('', '2151c4b970eff0071948dbbc19066aa4'))
#prepareResults(buildReq('hash', '2jkasdhfklasdjfh4'))
#prepareResults(buildReq('domain', 'a'))