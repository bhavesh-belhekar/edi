import argparse
import os
from datetime import datetime, timedelta, timezone
from generators.auth_generator import AuthEventGenerator
from shared.utils import to_json_str
import random

def main():
    """
    CENTRAL ORCHESTRATION SCRIPT for synthetic logs.
    Mixes normal and malicious activities over a simulated time window to 
    produce a realistic stream of events for downstream ML ingestion.
    """
    parser = argparse.ArgumentParser(description="Generate Synthetic Authentication Logs")
    parser.add_argument("--days", type=int, default=1, help="Number of days to simulate")
    parser.add_argument("--output-format", type=str, choices=["json", "ndjson"], default="ndjson")
    args = parser.parse_args()

    generator = AuthEventGenerator()
    base_date = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    
    all_events = []

    print(f"[*] Simulating {args.days} days of cyber activity...")

    for day in range(args.days):
        current_day = base_date + timedelta(days=day)
        
        # 1. Generate Normal Traffic
        # Assume 10-20 normal logins scattered per day across the workforce
        for _ in range(random.randint(10, 20)):
            all_events.append(generator.generate_normal_login(current_day))
            
        # 2. Inject Suspicious Admin Activity
        # 20% chance per day an admin logs in at 3 AM
        if random.random() < 0.2:
            all_events.append(generator.generate_admin_after_hours(current_day))
            
        # 3. Inject Brute Force Attacks
        # 30% chance per day an external attacker hits the perimeter
        if random.random() < 0.30:
            brute_burst = generator.generate_brute_force(
                base_time=current_day.replace(hour=random.randint(0, 23)),
                count=random.randint(15, 35) # Size of the brute force flood
            )
            all_events.extend(brute_burst)

    # Sort everything chronologically so downstream ML pipelines receive causal data
    all_events.sort(key=lambda x: x.timestamp)

    # Ensure output directory exists
    output_dir = "synthetic_logs/output"
    os.makedirs(output_dir, exist_ok=True)
    
    output_file = f"{output_dir}/auth_events.{args.output_format}"
    
    # Save the synthetic corpus
    with open(output_file, "w") as f:
        if args.output_format == "ndjson":
            for event in all_events:
                f.write(to_json_str(event) + "\n")
        else:
            # Native JSON dump
            # We output JSON array formatting by manually joining NDJSON lines as a single block
            json_array_str = "[\n" + ",\n".join([to_json_str(e) for e in all_events]) + "\n]"
            f.write(json_array_str)

    print(f"[+] Generated {len(all_events)} strictly-typed security events.")
    print(f"[+] Saved to: {output_file}")

if __name__ == "__main__":
    main()
