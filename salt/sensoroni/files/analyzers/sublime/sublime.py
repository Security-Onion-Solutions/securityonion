import json
import requests
import sys
import os
import helpers
import argparse


def checkConfigRequirements(conf):
    if "api_key" not in conf or len(conf['api_key']) == 0:
        sys.exit(126)


def buildReq(conf, artifact_value):
    headers = {"Authorization": "Bearer " + conf['api_key']}
    base_url = conf['base_url']
    if str(conf['live_flow']).lower() == "true":
        uri = "/v1/live-flow/raw-messages/analyze"
        data = {"create_mailbox": True, "mailbox_email_address": str(conf['mailbox_email_address']), "message_source_id": str(conf['message_source_id']), "raw_message": artifact_value}
    else:
        uri = "/v0/messages/analyze"
        data = {"raw_message": artifact_value,
                "run_active_detection_rules": True}
    url = base_url + uri
    return url, headers, data


def sendReq(url, headers, data):
    response = requests.request('POST',
                                url=url,
                                headers=headers,
                                data=json.dumps(data)).json()
    return response


def prepareResults(raw):
    matched = []
    if "rule_results" in raw:
        for r in raw["rule_results"]:
            if r["matched"] is True:
                matched.append(r)
        if len(matched) > 0:
            raw = matched
            status = "threat"
            summary = "malicious"
        else:
            raw = "No rules matched."
            status = "ok"
            summary = "harmless"
    elif "flagged_rules" in raw:
        if raw["flagged_rules"] is not None:
            status = "threat"
            summary = "malicious"
        else:
            status = "ok"
            summary = "harmless"
    results = {'response': raw, 'status': status, 'summary': summary}
    return results


def analyze(conf, input):
    checkConfigRequirements(conf)
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data["artifactType"])
    request = buildReq(conf, data["value"])
    response = sendReq(request[0], request[1], request[2])
    return prepareResults(response)


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description="Submit an email to Sublime Platform's EML Analyzer")
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar="CONFIG_FILE", default=dir + "/sublime.yaml", help='optional config file to use instead of the default config file')
    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
