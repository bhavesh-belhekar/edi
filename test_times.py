import json, glob
from dateutil import parser as date_parser

fs = glob.glob("synthetic_logs/output/*_dataset_*.ndjson")
evts = []
for f in fs:
    with open(f) as fp:
        for line in fp:
            evts.append(json.loads(line))

evts.sort(key=lambda x: date_parser.parse(x['timestamp']))

for i in range(5):
    print(evts[i]['timestamp'])
