import os
import sys
import argparse
import random
from collections import Counter
from datetime import datetime, timedelta, timezone

# Ensure the root project directory is in the sys.path so 'shared' module can be found
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from synthetic_logs.generators.auth_generator import AuthEventGenerator
from synthetic_logs.generators.endpoint_generator import EndpointEventGenerator
from shared.utils import to_json_str
from shared.logger import setup_logger

logger = setup_logger("SyntheticOrchestrator")

def generate_logs(count: int, format_type: str, seed: int):
    """
    Main orchestration engine for synthetic event generation.
    It builds a realistic temporal sequence by probabilistically picking
    the next behavior type, advancing time realistically, and validating schemas natively.
    """
    if seed is not None:
        random.seed(seed)
        logger.info(f"[*] Initialized with Random Seed: {seed}")

    auth_gen = AuthEventGenerator()
    endpoint_gen = EndpointEventGenerator()
    
    # Start simulation 7 days ago
    current_time = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(days=7)
    
    all_events = []
    
    # We use probabilities to decide the next 'action block'
    weights = [0.30, 0.40, 0.20, 0.10] # [auth_normal, endpoint_normal, attack, suspicious]
    
    logger.info(f"[*] Starting realistic event processing targeting {count} logs...")
    
    # Track statistics
    auth_count = 0
    endpoint_count = 0
    attack_count = 0
    
    while len(all_events) < count:
        # Step time forward by a random realistic delta
        current_time += timedelta(minutes=random.randint(1, 60))
        
        choice = random.choices(["auth_normal", "endpoint_normal", "attack", "suspicious"], weights=weights)[0]
        
        # Pick a random user and system for this "session"
        user_dict = random.choice(auth_gen.users)
        system_dict = random.choice(auth_gen.systems)
        
        if choice == "auth_normal":
            # Auth Phase
            auth_event = auth_gen.generate_successful_login(current_time)
            # Force user/system match for correlation
            auth_event.user.username = user_dict["username"]
            auth_event.user.role = user_dict["role"]
            auth_event.source.ip = system_dict["ip"]  # User logs in from a known IP
            
            all_events.append(auth_event)
            auth_count += 1
            
            # Post-Auth Endpoint Phase
            endpoint_events = endpoint_gen.generate_normal_activity(current_time, user_dict, system_dict)
            all_events.extend(endpoint_events)
            endpoint_count += len(endpoint_events)
            
        elif choice == "endpoint_normal":
            # Generate a burst of 5-10 endpoint events representing sustained user activity
            count_endpoint = random.randint(5, 10)
            for _ in range(count_endpoint):
                 endpoint_events = endpoint_gen.generate_normal_activity(current_time, user_dict, system_dict)
                 all_events.extend(endpoint_events)
                 endpoint_count += len(endpoint_events)
                 current_time += timedelta(minutes=random.randint(1, 5))
                 
            # 15% chance admin does admin things if they are admin
            if user_dict["role"] in ["admin", "system"] and random.random() < 0.15:
                admin_event = endpoint_gen.generate_admin_activity(current_time, user_dict, system_dict)
                all_events.append(admin_event)
                endpoint_count += 1
        
        elif choice == "suspicious":
            sub_choice = random.choices(["failed_login", "admin_after_hours", "unusual_ip"], weights=[0.4, 0.3, 0.3])[0]
            if sub_choice == "failed_login":
                event = auth_gen.generate_failed_login(current_time)
                all_events.append(event)
                auth_count += 1
            elif sub_choice == "admin_after_hours":
                event = auth_gen.generate_admin_after_hours(current_time)
                if event: 
                    all_events.append(event)
                    auth_count += 1
            elif sub_choice == "unusual_ip":
                event = auth_gen.generate_unusual_ip_login(current_time)
                all_events.append(event)
                auth_count += 1
                
        elif choice == "attack":
            # Brute force attack followed by successful login and attack chain
            attack_sequence = auth_gen.generate_brute_force_attack(current_time, count=random.randint(3, 8))
            all_events.extend(attack_sequence)
            auth_count += len(attack_sequence)
            
            # Attacker succeeds and generates endpoint attacks
            attacker_ip = attack_sequence[0].source.ip
            
            # Advance time slightly to simulate the breach
            current_time += timedelta(seconds=len(attack_sequence) * 2)
            
            malicious_success_login = auth_gen.generate_successful_login(current_time)
            malicious_success_login.user.username = user_dict["username"]
            malicious_success_login.source.ip = attacker_ip
            all_events.append(malicious_success_login)
            auth_count += 1
            attack_count += 1
            
            # Endpoint Attack Chain
            attack_events = endpoint_gen.generate_attack_chain(current_time, user_dict, system_dict, attacker_ip)
            all_events.extend(attack_events)
            endpoint_count += len(attack_events)
            attack_count += len(attack_events)

    # Cutoff if we over-generated due to an attack sequence appending a bulk array
    all_events = all_events[:count]
    
    logger.info(f"Generated {auth_count} Auth Events, {endpoint_count} Endpoint Events, {attack_count} Attack Events in chains")
    
    # Strictly sort by timestamp to ensure ML and Correlation dependencies operate perfectly
    all_events.sort(key=lambda x: x.timestamp)
    
    _save_and_summarize(all_events, format_type)

def _save_and_summarize(events, format_type):
    """
    Handles robust output management and statistical analysis of generated sequences.
    """
    output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'output'))
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(output_dir, f"auth_dataset_{timestamp_prefix}.{format_type}")
    
    logger.info(f"[*] Serializing {len(events)} events to {file_path} ...")
    
    # Statistical counters
    type_counts = Counter()
    severity_counts = Counter()
    top_ips = Counter()
    top_users = Counter()
    
    start_time = datetime.now()
    
    with open(file_path, "w") as f:
        if format_type == "ndjson":
            for event in events:
                f.write(to_json_str(event) + "\n")
                
                # Tracking
                type_counts[event.event_type] += 1
                severity_counts[event.severity] += 1
                if event.source and event.source.ip:
                    top_ips[event.source.ip] += 1
                if event.user and event.user.username:
                    top_users[event.user.username] += 1
        elif format_type == "json":
            json_blob = []
            for event in events:
                json_blob.append(to_json_str(event))
                type_counts[event.event_type] += 1
                severity_counts[event.severity] += 1
                if event.source and getattr(event.source, 'ip', None):
                    top_ips[event.source.ip] += 1
                if event.user and getattr(event.user, 'username', None):
                    top_users[event.user.username] += 1
            f.write("[\n" + ",\n".join(json_blob) + "\n]")
            
    elapsed = (datetime.now() - start_time).total_seconds()

    print("\n====================================================")
    print(" EXECUTION SUMMARY: SYNTHETIC DATASET GENERATION")
    print("====================================================")
    print(f"Total Events Generated : {len(events)}")
    print(f"Serialization Time     : {elapsed:.2f} seconds")
    print(f"Output File Location   : {file_path}")
    print("\n[ SEVERITY DISTRIBUTION ]")
    for sev, count in severity_counts.items():
        print(f"  - {sev.upper():10s} : {count}")
    print("\n[ EVENT TYPE DISTRIBUTION ]")
    for etype, count in type_counts.items():
        print(f"  - {etype:20s} : {count}")
    print("\n[ TOP 3 USERS ]")
    for user, count in top_users.most_common(3):
        print(f"  - {user:20s} : {count} events")
    print("\n[ TOP 3 SOURCE IPS (INCLUDING ATTACKERS) ]")
    for ip, count in top_ips.most_common(3):
        print(f"  - {ip:15s} : {count} events")
    print("====================================================\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Incident Response: Enterprise Synthetic Log Generator")
    parser.add_argument("--count", type=int, default=1000, help="Total number of security events to generate")
    parser.add_argument("--format", type=str, choices=["json", "ndjson"], default="ndjson", help="Output file serialization format")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for deterministic dataset generation")
    args = parser.parse_args()

    generate_logs(args.count, args.format, args.seed)
