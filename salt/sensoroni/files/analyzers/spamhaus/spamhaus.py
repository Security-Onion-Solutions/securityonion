import argparse
import dns.resolver
import dns.reversename
import json
import os
import helpers


def resolve(config, meta, ip):
    value = str(dns.reversename.from_address(ip)).replace("in-addr.arpa.", config["lookup_host"] + ".")
    resolver = dns.resolver.Resolver()
    if len(config["nameservers"]) > 0 and len(config["nameservers"][0]) > 0:
        resolver.nameservers = config["nameservers"]
    try:
        responses = resolver.resolve(value)
    except dns.resolver.NXDOMAIN:
        responses = []

    return responses


def prepareResults(responses):
    resultMap = {
        "127.0.0.2": {'severity': 200, 'summary': 'spam', 'status': 'caution'},
        "127.0.0.3": {'severity': 200, 'summary': 'spam', 'status': 'caution'},
        "127.0.0.4": {'severity': 300, 'summary': 'malicious', 'status': 'threat'},
        "127.0.0.5": {'severity': 300, 'summary': 'malicious', 'status': 'threat'},
        "127.0.0.6": {'severity': 300, 'summary': 'malicious', 'status': 'threat'},
        "127.0.0.7": {'severity': 300, 'summary': 'malicious', 'status': 'threat'},
        "127.0.0.10": {'severity': 100, 'summary': 'suspicious', 'status': 'caution'},
        "127.0.0.11": {'severity': 100, 'summary': 'suspicious', 'status': 'caution'},

        "127.0.1.2": {'severity': 200, 'summary': 'spam', 'status': 'caution'},
        "127.0.1.4": {'severity': 250, 'summary': 'phishing', 'status': 'threat'},
        "127.0.1.5": {'severity': 300, 'summary': 'malicious', 'status': 'threat'},
        "127.0.1.6": {'severity': 300, 'summary': 'malicious', 'status': 'threat'},
        "127.0.1.102": {'severity': 200, 'summary': 'spam', 'status': 'caution'},
        "127.0.1.103": {'severity': 200, 'summary': 'spam', 'status': 'caution'},
        "127.0.1.104": {'severity': 300, 'summary': 'malicious', 'status': 'threat'},
        "127.0.1.105": {'severity': 300, 'summary': 'malicious', 'status': 'threat'},
        "127.0.1.106": {'severity': 300, 'summary': 'malicious', 'status': 'threat'},
        "127.0.1.107": {'severity': 100, 'summary': 'suspicious', 'status': 'caution'},

        "127.255.255.252": {'severity': 1, 'summary': 'internal_failure', 'status': 'caution'},
        "127.255.255.254": {'severity': 2, 'summary': 'internal_failure', 'status': 'caution'},
        "127.255.255.255": {'severity': 3, 'summary': 'excessive_usage', 'status': 'caution'},
    }

    raw = []
    currentResult = {'severity': 0, 'summary': 'harmless', 'status': 'ok'}
    for response in responses:
        raw.append(response.to_text())
        if response.address in resultMap:
            result = resultMap[response.address]
            if currentResult is None or currentResult['severity'] < result['severity']:
                currentResult = result

    currentResult['response'] = raw
    return currentResult


def analyze(config, input):
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data["artifactType"])
    response = resolve(config, meta, data["value"])
    return prepareResults(response)


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description='Search Spamhaus for an IP')
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar="CONFIG_FILE", default=dir + "/spamhaus.yaml", help='optional config file to use instead of the default config file')

    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
