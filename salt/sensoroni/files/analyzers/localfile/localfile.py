import json
import helpers
import os
import argparse
import csv


def searchFile(artifact, csvfiles):
    dir = os.path.dirname(os.path.realpath(__file__))
    found = []
    for f in csvfiles:
        filename = dir + "/" + f
        with open(filename, "r") as csvfile:
            csvdata = csv.DictReader(csvfile)
            for row in csvdata:
                first_key = list(row.keys())[0]
                if artifact in row[first_key]:
                    row.update({"filename": filename})
                    found.append(row)
    if len(found) != 0:
        if len(found) == 1:
            results = found[0]
        else:
            results = found
    else:
        results = "No results"

    return results


def prepareResults(raw):
    if len(raw) > 0:
        if "No results" in raw:
            status = "ok"
            summary = "no_results"
        else:
            status = "info"
            summary = "suspicious"
    else:
        raw = {}
        status = "caution"
        summary = "internal_failure"
    response = raw
    results = {'response': response, 'status': status, 'summary': summary}
    return results


def analyze(conf, input):
    helpers.verifyNonEmptyListValue(conf, 'file_path')
    meta = helpers.loadMetadata(__file__)
    data = helpers.parseArtifact(input)
    helpers.checkSupportedType(meta, data["artifactType"])
    search = searchFile(data["value"], conf['file_path'])
    results = prepareResults(search)
    return results


def main():
    dir = os.path.dirname(os.path.realpath(__file__))
    parser = argparse.ArgumentParser(description='Search CSV file for a given artifact')
    parser.add_argument('artifact', help='the artifact represented in JSON format')
    parser.add_argument('-c', '--config', metavar="CONFIG_FILE", default=dir + "/localfile.yaml", help='optional config file to use instead of the default config file')

    args = parser.parse_args()
    if args.artifact:
        results = analyze(helpers.loadConfig(args.config), args.artifact)
        print(json.dumps(results))


if __name__ == "__main__":
    main()
