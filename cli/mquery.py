#!/usr/bin/python3
import argparse
import json
import sys
import time

import requests
from tabulate import tabulate
from tqdm import tqdm

parser = argparse.ArgumentParser(description='')
parser.add_argument('yara_file', help='Yara rule to be queried')
parser.add_argument('result_file', nargs='?', default='/tmp/mquery-last-result.json', help='output file')

args = parser.parse_args()


def print_matches(results):
    row = []

    for r in results:
        file = r['matched_path']
        meta = ', '.join(filter(lambda o: o, list(map(lambda o: r['metadata'][o].get('display_text'), r['metadata'].keys()))))
        row.append([file, meta])

    print(tabulate(row))


with open(args.yara_file, 'rb') as f:
    yara_rule = f.read()

res = requests.post('http://localhost:5000/query', json={'method': 'query', 'rawYara': yara_rule.decode('utf-8')})

out = res.json()

if 'error' in out:
    print(out['error'])
    sys.exit(1)

query_hash = res.json()['query_hash']
out = None
last_reported = 0

with tqdm(total=0) as pbar:
    while not out or out['job']['status'] not in ['cancelled', 'failed']:
        if out:
            time.sleep(1.0)

        res = requests.get('http://localhost:5000/status/{}'.format(query_hash))
        out = res.json()

        diff = int(out['job'].get('files_processed', 0)) - last_reported
        pbar.total = int(out['job'].get('total_files', 0))
        pbar.update(diff)
        last_reported += diff
        pbar.set_description(out['job']['status'])

        if out['job']['status'] == 'done':
            tagged = sum(map(lambda m: 1 if m['metadata_available'] else 0, out['matches']))
            pbar.total = len(out['matches'])
            pbar.n = tagged
            pbar.refresh()
            pbar.set_description('tagging')

            if tagged >= len(out['matches']):
                break


if out['job']['status'] == 'done':
    print_matches(out['matches'])

    with open(args.result_file, 'w') as f:
        f.write(json.dumps(out['matches'], indent=4, sort_keys=True))
else:
    sys.stderr.write(out['job']['error'])
