import requests
import argparse
import json
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
        print(response.json())
        return response.json()

testHashQuery('2151c4b970eff0071948dbbc19066aa4')
print("------------------------------------------------------------------------")
testIPQuery("139.180.203.104")

#Questions
#Do we need submission for (API KEY)?
#What data would you like to see from the JSON output?

