import os
import json
import glob
import time
import argparse
from datetime import datetime
from dateutil import parser as date_parser

def load_latest_datasets(output_dir):
    all_files = glob.glob(f"{output_dir}/*dataset_*.ndjson")
    if not all_files:
        return []
        
    timestamps = set()
    for f in all_files:
        basename = os.path.basename(f)
        parts = basename.replace('.ndjson', '').split('_dataset_')
        if len(parts) > 1:
            timestamps.add(parts[1])
            
    latest_ts = sorted(list(timestamps))[-1]
    latest_files = glob.glob(f"{output_dir}/*dataset_{latest_ts}.ndjson")
    
    events = []
    for f in latest_files:
        source = os.path.basename(f).split('_dataset')[0]
        with open(f, 'r') as fp:
            for line in fp:
                try:
                    record = json.loads(line.strip())
                    record['_source_type'] = source
                    record['_raw_line'] = line.strip()
                    events.append(record)
                except json.JSONDecodeError:
                    pass
    return events

def stream_events(events, wazuh_logs_dir, speed_multiplier=1.0, continuous=False):
    if not events:
        print("No events to stream.")
        return

    events.sort(key=lambda x: date_parser.parse(x['timestamp']))

    print(f"[*] Starting telemetry replay of {len(events)} events.")
    print(f"[*] Speed multiplier: {speed_multiplier}x")
    print(f"[*] Output directory: {wazuh_logs_dir}")

    while True:
        first_event_time = date_parser.parse(events[0]['timestamp'])
        start_real_time = time.time()

        for idx, event in enumerate(events):
            event_time = date_parser.parse(event['timestamp'])
            
            simulated_offset = (event_time - first_event_time).total_seconds()
            
            target_real_time = start_real_time + (simulated_offset / speed_multiplier)
            
            now = time.time()
            if target_real_time > now:
                sleep_duration = target_real_time - now
                if sleep_duration > 0.5:
                    sleep_duration = 0.5  # Cap the wait time between events to 0.5 seconds
                time.sleep(sleep_duration)

            log_file = os.path.join(wazuh_logs_dir, f"{event['_source_type']}.log")
            
            with open(log_file, 'a') as f:
                f.write(event['_raw_line'] + '\n')
            
            if idx % 10 == 0 or event.get('severity') in ['high', 'critical']:
                sev = event.get('severity', 'info').upper()
                src = event.get('_source_type')
                print(f"[{datetime.now().strftime('%H:%M:%S')}] [{sev}] -> {src}.log: {event.get('event_type')} | ID: {event.get('correlation', {}).get('attack_chain_id', 'N/A')}")

        if not continuous:
            print("[*] Streaming completed successfully.")
            break
        print("[*] Continuous mode enabled. Restarting stream...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay synthetic telemetry into Wazuh monitored directories.")
    parser.add_argument("--speed", type=float, default=1.0, help="Playback speed multiplier.")
    parser.add_argument("--continuous", action="store_true", help="Loop the dataset infinitely.")
    parser.add_argument("--input-dir", type=str, default="synthetic_logs/output", help="Directory containing NDJSON datasets.")
    parser.add_argument("--output-dir", type=str, default="wazuh_logs", help="Directory for Wazuh to monitor.")
    
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    loaded_events = load_latest_datasets(args.input_dir)
    stream_events(loaded_events, args.output_dir, args.speed, args.continuous)
