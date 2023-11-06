import requests
import json
#response=requests.get("https://localhost.com:9200", auth=('RyanH','2."XCvcfSZi95sX'))
#user name = elastic
#password = adminadmin
#verify is added solely because of cert issue, need to somehow fix that
#does not work here but works in vm, my guess is it needs to be installed in the same environment
#original code
#replace hash with the actual observable type
query = {
    "from" : 0, "size" : 1,
    "query": {
        "wildcard": {
            "hash": "*"
        },
    
    
    }
}
headers = {
        'Content-Type':'application/json',
}
data=json.dumps(query)
response=requests.post("https://192.168.56.106:9200/_all/_search", auth=('elastic','adminadmin'), verify = False, headers=headers, data= data)
print(response.json())
#without the index name it returns so much havent looked into seeing if it is the data we want
def buildReq(observableType, numberOfResults):    
    #need to put size in
    #query that looks for every observable type in every document/index
    query = {
        "from" : 0, "size" : numberOfResults,
        "query": {
            "wildcard": {
                observableType: "*"
            }
        }
    }
    qterm=json.dumps(query)
    return qterm
def sendReq(meta, index, query):
    headers = {
        'Content-Type':'application/json',
    }
    url = meta['baseUrl']
    url = "https://localhost:9200" + index + '_search' #urls needs to be replaced with actual local host/vm ip need to look into this
    authUser = meta['authUser']
    authPWD = meta['authPWD']
    response = requests.post(url, auth = (authUser,authPWD), verify = False, data = query, headers= headers)
    return response.json()
#testing
def lookValue(raw, observable):
    return raw['_source'][observable]

