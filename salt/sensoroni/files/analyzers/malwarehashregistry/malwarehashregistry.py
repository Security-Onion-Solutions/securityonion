import json
import helpers
import argparse
import datetime
from whois import NICClient


def sendReq(hash):
    server = "hash.cymru.com"
    flags = 0
    options = {"whoishost": server}
    nic_client = NICClient()
    response = nic_client.whois_lookup(options, hash, flags).rstrip()
    hash = response.split(' ')[0]
    lastSeen = response.split(' ')[1]
    if lastSeen == "NO_DATA":
        avPct = 0
    else:
        avPct = response.split(' ')[2]
        lastSeen = datetime.datetime.fromtimestamp(int(lastSeen)).strftime("%Y-%d-%m %H:%M:%S")
    raw = {"hash": hash, "last_seen": lastSeen, "av_detection_percentage": int(avPct)}
    return raw


def prepareResults(raw):
    if raw and "last_seen" in raw:
        if raw["last_seen"] == "NO_DATA":
            status = "ok"
            summary = "no_results"
        elif raw["av_detection_percentage"] < 1:
            status = "ok"
            summary = "harmless"
        elif raw["av_detection_percentage"] in range(1, 50):
            status = "caution"
            summary = "suspicious"
        elif raw["av_detection_percentage"] in range(51, 100):
            status = "threat"
            summary = "malicious"
    else:
        status = "caution"
        summary = "internal_failure"
    results = {'response': raw, 'summary': summary, 'status': status}
    return results


def analyze(input):
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data["artifactType"])
    response = sendReq(data["value"])
    return prepareResults(response)


def main():
    parser = argparse.ArgumentParser(description='Search Team Cymru Malware Hash Registry for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')

    args = parser.parse_args()
    if args.artifact:
        results = analyze(args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
