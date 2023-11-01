from elasticsearch import Elasticsearch
import requests

#response=requests.get("https://localhost.com:9200", auth=('RyanH','2."XCvcfSZi95sX'))
#user name = elastic
#password = adminadmin
#verify is added solely because of cert issue, need to somehow fix that
#does not work here but works in vm, my guess is it needs to be installed in the same environment
#original code


# response=requests.get("https://localhost:9200", auth=('elastic','adminadmin'), verify = False)
# print(response.json())

#without the index name it returns so much havent looked into seeing if it is the data we want
def sendReq(meta, index):
    url = meta['baseUrl']
    url = "https://localhost:9200" + index + '_search'
    authUser = meta['authUser']
    authPWD = meta['authPWD']
    response = requests.get(url, auth = (authUser,authPWD), verify = False)
    return response.json()

#testing
def lookValue(raw, observable):
    return raw['_source'][observable]

