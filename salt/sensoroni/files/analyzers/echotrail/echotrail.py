import json
import os
import sys
import requests
#import helpers
import argparse


def testHash(hashVar):    
    testHash = hashVar
    url = "https://api.echotrail.io/" + testHash
    headers = {"Key": "I7TXsJcq6p2TVwxnsFKcO5rflwLlhjewarRkUPq7I7TXsJcq6p2TVwxnsFKcO5rflwLlhjewarRkUPq7"}
    response = requests.request('GET', url=url, headers=headers)
    return response.json()

print(testHash("438b6ccd84f4dd32d9684ed7d58fd7d1e5a75fe3f3d12ab6c788e6bb0ffad5e7"))