import json
import helpers
import argparse
import whoisit


def sendReq(domain):
    whoisit.bootstrap()
    try:
        results = whoisit.domain(domain, raw=True)
    except whoisit.errors.ResourceDoesNotExist:
        results = "Not found."
    except whoisit.errors.QueryError as error:
        results = "QueryError: " + str(error)
    return results


def prepareResults(raw):
    if raw:
        if "Not found." in raw:
            status = "info"
            summary = "no_results"
        elif "QueryError" in raw:
            status = "caution"
            summary = "invalid_input"
        else:
            status = "info"
            summary = "analysis_complete"
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
    parser = argparse.ArgumentParser(description='Query RDAP server for WHOIS-like information for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')

    args = parser.parse_args()
    if args.artifact:
        results = analyze(args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
