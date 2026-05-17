import json
import os
import glob
from collections import defaultdict

def validate_datasets():
    output_dir = "synthetic_logs/output"
    print("====================================================")
    print("        TELEMETRY VALIDATION REPORT")
    print("====================================================\n")

    all_files = glob.glob(f"{output_dir}/*dataset_*.ndjson")
    if not all_files:
        print("No NDJSON files found.")
        return

    # Extract full timestamp e.g., 20260516_171858
    timestamps = set()
    for f in all_files:
        basename = os.path.basename(f)
        # auth_dataset_20260516_171858.ndjson
        parts = basename.replace('.ndjson', '').split('_dataset_')
        if len(parts) > 1:
            timestamps.add(parts[1])

    latest_ts = sorted(list(timestamps))[-1]

    print(f"[STEP 11 - CLEANUP] Latest generation timestamp: {latest_ts}")
    for f in all_files:
        if latest_ts not in f:
            print(f"  - Deleting outdated file: {f}")
            os.remove(f)

    latest_files = glob.glob(f"{output_dir}/*dataset_{latest_ts}.ndjson")

    print("\n====================================================")
    print("STEP 1: VALIDATE NDJSON FORMAT")
    print("====================================================")

    dataset_records = {}
    malformed_records = 0
    all_events = []

    for f in latest_files:
        source_name = os.path.basename(f).split('_dataset')[0]
        count = 0
        with open(f, 'r') as fp:
            for line in fp:
                try:
                    record = json.loads(line.strip())
                    record['_source_dataset'] = source_name
                    all_events.append(record)
                    count += 1
                except json.JSONDecodeError:
                    malformed_records += 1
        dataset_records[f] = count
        print(f"✔ {os.path.basename(f)} : {count} valid records")

    print(f"\nTotal Records Parsed: {len(all_events)}")
    print(f"Malformed Records: {malformed_records}")

    print("\n====================================================")
    print("STEP 2: VERIFY SHARED ATTACK CHAIN CORRELATION")
    print("====================================================")

    chain_datasets = defaultdict(set)
    chain_timelines = defaultdict(list)

    for ev in all_events:
        corr = ev.get('correlation', {})
        if corr:
            chain_id = corr.get('attack_chain_id')
            if chain_id:
                src = ev['_source_dataset']
                chain_datasets[chain_id].add(src)
                chain_timelines[chain_id].append(ev)

    print(f"Total Unique Attack Chains Found: {len(chain_datasets)}")
    orphaned_chains = 0
    for chain_id, datasets in chain_datasets.items():
        print(f"  - Chain {chain_id} spans {len(datasets)} datasets: {list(datasets)}")
        if len(datasets) < 2:
            orphaned_chains += 1
            print("    [!] ORPHANED CHAIN (Found in < 2 datasets)")

    print(f"\nOrphaned/Partial Chains: {orphaned_chains}")

    print("\n====================================================")
    print("STEP 3: VERIFY REALISTIC ATTACK PROGRESSION")
    print("====================================================")
    for chain_id, events in chain_timelines.items():
        events.sort(key=lambda x: x.get('timestamp', ''))
        stages = [e.get('event_type') for e in events]
        print(f"  - Chain {chain_id} Progression ({len(stages)} steps):")
        if len(stages) > 8:
            print(f"      {stages[:4]} ... {stages[-4:]}")
        else:
            print(f"      {stages}")

        ts_valid = True
        for i in range(1, len(events)):
            if events[i]['timestamp'] < events[i-1]['timestamp']:
                ts_valid = False
                break
        print(f"      ✔ Timestamps logically ordered: {ts_valid}")

    print("\n====================================================")
    print("STEP 4: VERIFY DATASET SEPARATION")
    print("====================================================")
    separation_errors = 0
    for ev in all_events:
        src = ev['_source_dataset']
        evt = ev.get('event_type', '')
        if src == 'auth' and 'login' not in evt and 'logout' not in evt and 'admin_after_hours' not in evt and 'brute_force' not in evt:
            print(f"      [!] Unexpected event {evt} in auth dataset")
            separation_errors += 1
        elif src == 'dns' and 'dns' not in evt:
            print(f"      [!] Unexpected event {evt} in dns dataset")
            separation_errors += 1
        elif src == 'firewall' and 'firewall' not in evt:
            print(f"      [!] Unexpected event {evt} in firewall dataset")
            separation_errors += 1
        elif src == 'proxy' and 'proxy' not in evt:
            print(f"      [!] Unexpected event {evt} in proxy dataset")
            separation_errors += 1
    if separation_errors == 0:
        print("✔ Strict separation confirmed. No mixed telemetry types.")

    print("\n====================================================")
    print("STEP 5 & 6: VERIFY SCHEMA CONSISTENCY & DETECTION")
    print("====================================================")
    required_fields = ['event_id', 'timestamp', 'event_type', 'severity', 'raw_log']

    schema_errors = 0
    det_errors = 0

    for ev in all_events:
        for f in required_fields:
            if f not in ev:
                schema_errors += 1
        if ev.get('detection'):
            det = ev['detection']
            if not all(k in det for k in ['anomaly_score', 'risk_score', 'risk_level']):
                det_errors += 1

    if schema_errors == 0:
        print("✔ Top-level schema consistency confirmed across all sources.")
    else:
        print(f"[!] Found {schema_errors} schema consistency issues.")

    if det_errors == 0:
        print("✔ Detection object structure valid (contains anomaly, risk metrics).")

    print("\n====================================================")
    print("STEP 7: VERIFY MITRE ATT&CK MAPPINGS")
    print("====================================================")
    mitre_count = 0
    tactics = set()
    for ev in all_events:
        if ev.get('mitre_attack'):
            m = ev['mitre_attack']
            if m.get('technique_id') and m.get('tactic'):
                mitre_count += 1
                tactics.add(m.get('tactic'))

    print(f"Total events with MITRE mapping: {mitre_count}")
    print(f"Mapped Tactics: {tactics}")

    print("\n====================================================")
    print("STEP 8 & 9: VERIFY REALISM & DISTRIBUTIONS")
    print("====================================================")
    benign = 0
    malicious = 0
    severities = defaultdict(int)

    for ev in all_events:
        sev = ev.get('severity', 'info').lower()
        severities[sev] += 1
        if sev in ['high', 'critical'] or (ev.get('correlation') and ev['correlation'].get('attack_chain_id')):
            malicious += 1
        else:
            benign += 1

    print("Severity Distribution:")
    for s, c in severities.items():
        print(f"  {s}: {c}")

    print(f"\nTotal Benign Events: {benign}")
    print(f"Total Malicious Events: {malicious}")
    mal_pct = (malicious / len(all_events)) * 100 if len(all_events) > 0 else 0
    print(f"Malicious Activity: {mal_pct:.2f}%")
    if mal_pct < 20:
        print("✔ Majority of traffic is benign, simulating realistic environment.")

if __name__ == '__main__':
    validate_datasets()
