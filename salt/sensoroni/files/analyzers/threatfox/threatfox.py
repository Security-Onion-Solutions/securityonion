import argparse
import yaml
import requests
import json
import os
import helpers
from pprint import pprint
# pprint should (probably?) not be present in the final version.


def buildReq(observ_type, observ_value):
        """buildReq takes an input observable type and an input observable value and properly formats them
        such that we can send a python dictionary object to sendReq."""
        
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
        """sendReq takes metadata (the threatfox.yaml file or an optional config file) and 
        a query (dict object from buildReq containing observable type/value) to request a 
        report on an observable."""
        
        url = meta['base_url']
        response = requests.post(url, json.dumps(query))
        return response.json()


def prepareResults(raw):
        """prepareResults takes json data from sendReq and compiles the response with a
        summary and status report."""        
        if raw != {} and raw['query_status'] == 'ok':
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
                        
        # 'illegl_hash' is not a typo!
        elif raw != {} and raw['query_status'] in ['no_result', 'illegal_search_term', 'illegl_hash']:
                # not sure if I should set raw to empty here, as leaving it as-is would
                # give more information other than "no result"
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
# code is invalid now, but the values can be saved for tests

#prepareResults(buildReq('hash','2151c4b970eff0071948dbbc19066aa4')))
#prepareResults(buildReq('hash','2151c4b970eff0071948dbbc19066ab4'))
#prepareResults(buildReq('domain', 'http://google.com'))
#prepareResults(buildReq('domain', 'https://google.com'))
#prepareResults(buildReq('', '2151c4b970eff0071948dbbc19066aa4'))
#prepareResults(buildReq('hash', '2jkasdhfklasdjfh4'))
#prepareResults(buildReq('domain', 'a'))


#py -m threatfox '{\"artifactType\":\"hash\", \"value\":\"2151c4b970eff0071948dbbc19066aa4\"}'

def analyze(conf, input):
        # loads the artifact string into a dict and sends it to be checked 
        # and formatted by buildReq
        data = helpers.parseArtifact(input)
        #meta?
        query = buildReq(data["artifactType"], data["value"])      
        response = sendReq(conf, query)
        return prepareResults(response)

def main():
        # gets current directory (for finding yaml file)
        dir = os.path.dirname(os.path.realpath(__file__))
        
        # create an ArgumentParser object for passing in arguments via command line
        parser = argparse.ArgumentParser(description='Query Threatfox for a suspect domain, hash, or IP')
        parser.add_argument('artifact', help='JSON with artifact type and value')
        parser.add_argument('-c', '--config', metavar='CONFIG_FILE', default=dir + '\\threatfox.yaml', 
                        help='Parameter for the use of a custom config file in place of the default yaml')

        # by default, the arg parser stores each argument in a dictionary. parse_args separates
        # the arguments into their correspondent parts. they can be accessed as a property of
        # a Namespace(?) object.
        args = parser.parse_args()
        
        # run if an artifact argument was given
        if args.artifact:              
                results = analyze(helpers.loadConfig(args.config), args.artifact)
                pprint(results)
                

if __name__ == '__main__':
        main()