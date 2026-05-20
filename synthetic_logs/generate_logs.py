import os
import sys
import argparse
import random
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

# Ensure the root project directory is in the sys.path so 'shared' module can be found
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from synthetic_logs.generators.auth_generator import AuthEventGenerator
from synthetic_logs.generators.endpoint_generator import EndpointEventGenerator
from synthetic_logs.generators.dns_generator import DNSEventGenerator
from synthetic_logs.generators.firewall_generator import FirewallEventGenerator
from synthetic_logs.generators.proxy_generator import ProxyEventGenerator
from shared.utils import to_json_str
from shared.logger import get_logger

logger = get_logger("SyntheticOrchestrator")


# ==============================================================================
# ATTACK SCENARIO — Shared correlation context across all datasets
# ==============================================================================

@dataclass
class AttackScenario:
    """
    Pre-generated correlation context that binds events across independent
    telemetry datasets. Each scenario represents one multi-stage attack chain
    observable across auth, endpoint, DNS, firewall, and proxy logs.
    """
    attack_chain_id: str
    attacker_ip: str
    target_user: Dict[str, Any]
    target_system: Dict[str, Any]
    start_time: datetime
    is_known_attack: bool = True
    mutation_seed: str = ""
    last_event_ids: Dict[str, str] = field(default_factory=dict)


# ==============================================================================
# FINGERPRINT MUTATION LOGIC
# ==============================================================================

# KNOWN vs UNKNOWN ratio (default 70% KNOWN, 30% UNKNOWN)
DEFAULT_KNOWN_RATIO = 0.70


def _should_be_known_attack(known_ratio: float = DEFAULT_KNOWN_RATIO) -> bool:
    """Decide if this attack should be KNOWN (matches fingerprint) or UNKNOWN (new fingerprint)."""
    return random.random() < known_ratio


def _set_correlation_id(event, chain_id: str):
    """Safely set correlation.attack_chain_id, initializing correlation if needed."""
    from shared.schemas import CorrelationInfo
    if event.correlation is None:
        event.correlation = CorrelationInfo()
    event.correlation.attack_chain_id = chain_id


def _mutate_fingerprint_fields(event, is_unknown: bool, mutation_seed: str):
    """
    Mutate fields that affect fingerprint uniqueness to create UNKNOWN attacks.
    
    Fingerprint now includes (see src/services/signature_engine/fingerprint.py):
      - event_type, severity
      - source.ip, source.geo, source.port
      - destination.ip, destination.port, destination.hostname
      - user.username
      - process.name, process.command_line (hashed)
      - file.file_hash, file.file_path (hashed)
      - mitre.technique_id, mitre.tactic
      - correlation.attack_chain_id
      - behavioral features
    
    To create UNKNOWN attacks, we mutate these fields so the fingerprint changes:
      - event_type with random suffix
      - random IPs (source/destination)
      - random ports
      - random usernames
      - random process names/commands
      - random file hashes
      - random MITRE technique IDs
      - new attack chain IDs
    
    KNOWN attacks keep these fields consistent so fingerprint matches stored signatures.
    """
    if not is_unknown:
        # KNOWN ATTACK: Keep fingerprint-consistent fields stable
        # This ensures fingerprint matches previous runs
        logger.debug(f"KNOWN_ATTACK: fingerprint fields unchanged for {event.event_id}")
        return
    
    # UNKNOWN ATTACK: Mutate fingerprint-critical fields
    
    # 1. Mutate event_type with random suffix (changes fingerprint)
    event_type_base = event.event_type
    random_suffix = random.choice(["_variant", "_new", "_modified", "_extended", "_alt", "_custom", ""])
    if random_suffix:
        event.event_type = f"{event_type_base}{random_suffix}"
    
    # 2. Mutate severity (changes fingerprint)
    event.severity = random.choice(["low", "medium", "high", "critical"])
    
    # 3. Mutate source IP (major fingerprint change)
    if event.source and event.source.ip:
        # Generate random external IP
        random_ip = f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        event.source.ip = random_ip
        event.source.geo = random.choice(["RU", "CN", "IR", "KP", "SY", "Unknown-Region", "PK", "UA"])
    
    # 4. Mutate source port (changes fingerprint)
    if event.source:
        event.source.port = random.randint(1024, 65535)
    
    # 5. Mutate destination IP (major fingerprint change)
    if event.destination and event.destination.ip:
        random_dst_ip = f"10.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        event.destination.ip = random_dst_ip
    
    # 6. Mutate destination port
    if event.destination:
        event.destination.port = random.randint(1, 65535)
    
    # 7. Mutate username (major fingerprint change)
    if event.user and event.user.username:
        random_users = ["hacker_temp", "attacker_acct", "unknown_user", "test_admin", "malware_user", "intruder"]
        event.user.username = random.choice(random_users)
    
    # 8. Mutate process name
    if event.process and event.process.name:
        random_procs = ["powershell", "cmd", "bash", "sh", "perl", "python3", "ruby", "mshta", "rundll32", "regsvr32"]
        event.process.name = random.choice(random_procs)
    
    # 9. Mutate process command line
    if event.process and event.process.command_line:
        # Add random encoded parameter
        random_params = [f"-enc {random.randint(1000,9999)}", f"-w hidden", f"-nop", f"/c echo", f"| sh", f"2>&1"]
        event.process.command_line += " " + random.choice(random_params)
    
    # 10. Mutate file hash
    if event.file and event.file.file_hash:
        # Generate random hash-like string
        event.file.file_hash = f"{random.randint(100000,999999)}{random.randint(100000,999999)}{random.randint(100000,999999)}"
    
    # 11. Mutate behavioral features (changes fingerprint signature)
    if event.behavioral_features:
        bf = event.behavioral_features
        bf.odd_hour_activity = random.choice([True, False])
        bf.beaconing_detected = random.choice([True, False])
        bf.high_entropy_domain = random.choice([True, False])
        bf.failed_attempts = random.randint(0, 10)
        bf.login_frequency = random.randint(0, 20)
        bf.is_privileged_user = random.choice([True, False, None])
    
    # 12. Mutate attack chain ID (completely changes fingerprint)
    if event.correlation is not None and event.correlation.attack_chain_id:
        new_chain_id = f"mutated_{mutation_seed}_{random.randint(1000,9999)}_{event.correlation.attack_chain_id}"
        event.correlation.attack_chain_id = new_chain_id
    
    # 13. Mutate MITRE technique (if present)
    if event.mitre_attack:
        random_techniques = ["T1110", "T1078", "T1059", "T1003", "T1082", "T1083", "T1055", "T1021", "T1047", "T1219"]
        event.mitre_attack.technique_id = random.choice(random_techniques)
    
    logger.info(f"[UNKNOWN_ATTACK] event_id={event.event_id} event_type={event.event_type} "
                f"src_ip={event.source.ip if event.source else 'N/A'} "
                f"dst_ip={event.destination.ip if event.destination else 'N/A'} "
                f"user={event.user.username if event.user else 'N/A'} "
                f"fingerprint_mutated=True")


# ==============================================================================
# MAIN ORCHESTRATOR
# ==============================================================================

def generate_all_telemetry(count: int, attack_count: int, format_type: str, seed: int, known_ratio: float = DEFAULT_KNOWN_RATIO):
    """
    Main orchestration engine for multi-source synthetic telemetry generation.

    Generates 5 independent datasets with shared cross-dataset correlation:
      1. auth_dataset     — Authentication events (logins, failures, brute force)
      2. endpoint_dataset — Endpoint telemetry (processes, files, attack chains)
      3. dns_dataset      — DNS queries (benign, typo-squat, DGA, tunneling, C2)
      4. firewall_dataset — Firewall logs (allow/deny, lateral movement, C2, exfil)
      5. proxy_dataset    — Web proxy logs (browsing, downloads, phishing, C2 beacon)
    
    Parameters:
      known_ratio: Proportion of attacks that should be KNOWN (matching fingerprints).
                  Default 0.70 means 70% KNOWN, 30% UNKNOWN.
    """
    if seed is not None:
        random.seed(seed)
        logger.info(f"[*] Initialized with Random Seed: {seed}")

    logger.info(f"[*] Attack classification: {known_ratio*100:.0f}% KNOWN attacks, {(1-known_ratio)*100:.0f}% UNKNOWN attacks")

    # Initialize all generators
    auth_gen = AuthEventGenerator()
    endpoint_gen = EndpointEventGenerator()
    dns_gen = DNSEventGenerator()
    firewall_gen = FirewallEventGenerator()
    proxy_gen = ProxyEventGenerator()

    # Simulation window: 7 days back from now
    sim_start = datetime.now(timezone.utc).replace(second=0, microsecond=0) - timedelta(days=7)

    # Separate event collectors per telemetry source
    auth_events = []
    endpoint_events = []
    dns_events = []
    firewall_events = []
    proxy_events = []

    # ==================================================================
    # PHASE A: Pre-generate Attack Scenarios with KNOWN/UNKNOWN classification
    # ==================================================================
    logger.info(f"[*] Pre-generating {attack_count} cross-dataset attack scenarios...")

    attack_scenarios = []
    known_count = 0
    unknown_count = 0
    
    for _ in range(attack_count):
        chain_id = f"attack_chain_{uuid.uuid4().hex[:8]}"
        attacker_ip = random.choice(auth_gen.ips["known_malicious_ips"])
        target_user = random.choice(auth_gen.users)
        target_system = random.choice(auth_gen.systems)
        
        # Determine if this attack should be KNOWN or UNKNOWN
        is_known = _should_be_known_attack(known_ratio)
        mutation_seed = uuid.uuid4().hex[:8]
        
        if is_known:
            known_count += 1
        else:
            unknown_count += 1
        
        # Spread attacks across the 7-day window
        attack_start = sim_start + timedelta(
            hours=random.randint(6, 160),
            minutes=random.randint(0, 59)
        )
        attack_scenarios.append(AttackScenario(
            attack_chain_id=chain_id,
            attacker_ip=attacker_ip,
            target_user=target_user,
            target_system=target_system,
            start_time=attack_start,
            is_known_attack=is_known,
            mutation_seed=mutation_seed,
        ))
    
    logger.info(f"[*] Attack classification results: {known_count} KNOWN, {unknown_count} UNKNOWN")

    # Sort attacks chronologically so timeline is consistent
    attack_scenarios.sort(key=lambda s: s.start_time)

    # ==================================================================
    # PHASE B: Generate benign background traffic for each source
    # ==================================================================
    logger.info(f"[*] Generating ~{count} benign events per telemetry source...")

    current_time = sim_start

    # --- AUTH benign events ---
    auth_target = count
    while len(auth_events) < auth_target:
        current_time += timedelta(minutes=random.randint(1, 45))
        user_dict = random.choice(auth_gen.users)

        choice = random.choices(
            ["login", "failed", "admin_after_hours", "unusual_ip", "logout"],
            weights=[0.50, 0.15, 0.05, 0.05, 0.25]
        )[0]

        if choice == "login":
            ev = auth_gen.generate_successful_login(current_time, user_dict)
            auth_events.append(ev)
        elif choice == "failed":
            ev = auth_gen.generate_failed_login(current_time, user_dict)
            auth_events.append(ev)
        elif choice == "admin_after_hours":
            ev = auth_gen.generate_admin_after_hours(current_time)
            if ev:
                auth_events.append(ev)
        elif choice == "unusual_ip":
            ev = auth_gen.generate_unusual_ip_login(current_time)
            auth_events.append(ev)
        elif choice == "logout":
            ev = auth_gen.generate_logout(current_time, user_dict)
            auth_events.append(ev)

    # --- ENDPOINT benign events ---
    current_time = sim_start
    endpoint_target = count
    while len(endpoint_events) < endpoint_target:
        current_time += timedelta(minutes=random.randint(1, 30))
        user_dict = random.choice(endpoint_gen.users)
        system_dict = random.choice(endpoint_gen.systems)

        choice = random.choices(
            ["normal", "admin"],
            weights=[0.90, 0.10]
        )[0]

        if choice == "normal":
            evts = endpoint_gen.generate_normal_activity(current_time, user_dict, system_dict)
            endpoint_events.extend(evts)
        elif choice == "admin" and user_dict.get("is_admin"):
            ev = endpoint_gen.generate_admin_activity(current_time, user_dict, system_dict)
            endpoint_events.append(ev)

    # --- DNS benign events ---
    current_time = sim_start
    dns_target = count
    while len(dns_events) < dns_target:
        current_time += timedelta(minutes=random.randint(1, 20))
        user_dict = random.choice(dns_gen.users)
        system_dict = random.choice(dns_gen.systems)

        choice = random.choices(
            ["benign", "typosquat"],
            weights=[0.92, 0.08]
        )[0]

        if choice == "benign":
            evts = dns_gen.generate_benign_dns(current_time, user_dict, system_dict)
            dns_events.extend(evts)
        elif choice == "typosquat":
            ev = dns_gen.generate_typosquat_query(current_time, user_dict, system_dict)
            dns_events.append(ev)

    # --- FIREWALL benign events ---
    current_time = sim_start
    fw_target = count
    while len(firewall_events) < fw_target:
        current_time += timedelta(minutes=random.randint(1, 15))
        user_dict = random.choice(firewall_gen.users)
        system_dict = random.choice(firewall_gen.systems)

        choice = random.choices(
            ["outbound", "internal", "denied"],
            weights=[0.50, 0.35, 0.15]
        )[0]

        if choice == "outbound":
            evts = firewall_gen.generate_normal_outbound(current_time, user_dict, system_dict)
            firewall_events.extend(evts)
        elif choice == "internal":
            ev = firewall_gen.generate_normal_internal(current_time, user_dict, system_dict)
            firewall_events.append(ev)
        elif choice == "denied":
            ev = firewall_gen.generate_denied_traffic(current_time, user_dict, system_dict)
            firewall_events.append(ev)

    # --- PROXY benign events ---
    current_time = sim_start
    proxy_target = count
    while len(proxy_events) < proxy_target:
        current_time += timedelta(minutes=random.randint(1, 25))
        user_dict = random.choice(proxy_gen.users)
        system_dict = random.choice(proxy_gen.systems)

        choice = random.choices(
            ["browsing", "update", "cloud"],
            weights=[0.60, 0.20, 0.20]
        )[0]

        if choice == "browsing":
            evts = proxy_gen.generate_normal_browsing(current_time, user_dict, system_dict)
            proxy_events.extend(evts)
        elif choice == "update":
            ev = proxy_gen.generate_software_update(current_time, user_dict, system_dict)
            proxy_events.append(ev)
        elif choice == "cloud":
            ev = proxy_gen.generate_cloud_access(current_time, user_dict, system_dict)
            proxy_events.append(ev)

    # ==================================================================
    # PHASE C: Inject correlated attack chains across ALL datasets
    # ==================================================================
    logger.info(f"[*] Injecting {len(attack_scenarios)} correlated attack chains across all datasets...")
    
    known_injected = 0
    unknown_injected = 0

    for scenario in attack_scenarios:
        t = scenario.start_time
        chain_id = scenario.attack_chain_id
        user = scenario.target_user
        system = scenario.target_system
        attacker_ip = scenario.attacker_ip
        prev_id = None
        is_known = scenario.is_known_attack
        mutation_seed = scenario.mutation_seed
        
        # Log attack classification
        if is_known:
            logger.info(f"[KNOWN_ATTACK] chain_id={chain_id} attacker_ip={attacker_ip} "
                        f"fingerprint_will_match=True")
            known_injected += 1
        else:
            logger.info(f"[UNKNOWN_ATTACK] chain_id={chain_id} attacker_ip={attacker_ip} "
                        f"mutation_seed={mutation_seed} fingerprint_will_mutate=True")
            unknown_injected += 1

        # --- Step 1: AUTH — Brute force + successful login ---
        brute_events = auth_gen.generate_brute_force_attack(t, count=random.randint(3, 6))
        for ev in brute_events:
            ev.source.ip = attacker_ip
            ev.user.username = user["username"]
            _set_correlation_id(ev, chain_id)
            # Apply fingerprint mutation for UNKNOWN attacks
            _mutate_fingerprint_fields(ev, not is_known, mutation_seed)
        auth_events.extend(brute_events)
        t += timedelta(seconds=len(brute_events) * 2)

        success_login = auth_gen.generate_successful_login(t, user)
        success_login.source.ip = attacker_ip
        success_login.source.geo = "External-Malicious"
        success_login.severity = "critical"
        _set_correlation_id(success_login, chain_id)
        if brute_events:
            success_login.correlation.related_events = [brute_events[-1].event_id]
        # Apply fingerprint mutation for UNKNOWN attacks
        _mutate_fingerprint_fields(success_login, not is_known, mutation_seed)
        auth_events.append(success_login)
        prev_id = success_login.event_id
        t += timedelta(seconds=random.randint(5, 15))

        # --- Step 2: ENDPOINT — Attack chain (powershell, mimikatz, file, reverse shell) ---
        attack_chain_events = endpoint_gen.generate_attack_chain(t, user, system, attacker_ip)
        for ev in attack_chain_events:
            _set_correlation_id(ev, chain_id)
            # Apply fingerprint mutation for UNKNOWN attacks
            _mutate_fingerprint_fields(ev, not is_known, mutation_seed)
        if attack_chain_events:
            attack_chain_events[0].correlation.related_events.append(prev_id)
        endpoint_events.extend(attack_chain_events)

        if attack_chain_events:
            prev_id = attack_chain_events[-1].event_id
            t = attack_chain_events[-1].timestamp + timedelta(seconds=random.randint(2, 10))

        # --- Step 3: DNS — C2 beaconing + optional DGA/tunneling ---
        dns_beacon_events = dns_gen.generate_malicious_beacon(t, user, system, chain_id, prev_id)
        for ev in dns_beacon_events:
            _mutate_fingerprint_fields(ev, not is_known, mutation_seed)
        dns_events.extend(dns_beacon_events)

        if dns_beacon_events:
            prev_id = dns_beacon_events[-1].event_id
            t = dns_beacon_events[-1].timestamp + timedelta(seconds=random.randint(2, 8))

        # 50% chance of DGA activity
        if random.random() < 0.5:
            dga_events = dns_gen.generate_dga_query(t, user, system, chain_id, prev_id)
            for ev in dga_events:
                _mutate_fingerprint_fields(ev, not is_known, mutation_seed)
            dns_events.extend(dga_events)
            if dga_events:
                prev_id = dga_events[-1].event_id
                t = dga_events[-1].timestamp + timedelta(seconds=random.randint(2, 8))

        # 40% chance of DNS tunneling
        if random.random() < 0.4:
            tunnel_events = dns_gen.generate_dns_tunneling(t, user, system, chain_id, prev_id)
            for ev in tunnel_events:
                _mutate_fingerprint_fields(ev, not is_known, mutation_seed)
            dns_events.extend(tunnel_events)
            if tunnel_events:
                prev_id = tunnel_events[-1].event_id
                t = tunnel_events[-1].timestamp + timedelta(seconds=random.randint(2, 8))

        # --- Step 4: FIREWALL — Lateral movement + C2 outbound + exfil ---
        lateral_events = firewall_gen.generate_lateral_movement(t, user, system, chain_id, prev_id)
        for ev in lateral_events:
            _mutate_fingerprint_fields(ev, not is_known, mutation_seed)
        firewall_events.extend(lateral_events)

        if lateral_events:
            prev_id = lateral_events[-1].event_id
            t = lateral_events[-1].timestamp + timedelta(seconds=random.randint(5, 20))

        c2_fw_event = firewall_gen.generate_c2_outbound(t, user, system, chain_id, prev_id)
        _mutate_fingerprint_fields(c2_fw_event, not is_known, mutation_seed)
        firewall_events.append(c2_fw_event)
        prev_id = c2_fw_event.event_id
        t += timedelta(seconds=random.randint(30, 120))

        exfil_event = firewall_gen.generate_data_exfil(t, user, system, chain_id, prev_id)
        _mutate_fingerprint_fields(exfil_event, not is_known, mutation_seed)
        firewall_events.append(exfil_event)
        prev_id = exfil_event.event_id
        t += timedelta(seconds=random.randint(5, 15))

        # --- Step 5: PROXY — Malicious download + C2 HTTP beacon ---
        download_event = proxy_gen.generate_malicious_download(t, user, system, chain_id, prev_id)
        _mutate_fingerprint_fields(download_event, not is_known, mutation_seed)
        proxy_events.append(download_event)
        prev_id = download_event.event_id
        t += timedelta(seconds=random.randint(10, 30))

        # 60% chance of phishing access in the chain
        if random.random() < 0.6:
            phish_event = proxy_gen.generate_phishing_access(t, user, system, chain_id, prev_id)
            _mutate_fingerprint_fields(phish_event, not is_known, mutation_seed)
            proxy_events.append(phish_event)
            prev_id = phish_event.event_id
            t += timedelta(seconds=random.randint(5, 15))

        c2_beacon_events = proxy_gen.generate_c2_http_beacon(t, user, system, chain_id, prev_id)
        for ev in c2_beacon_events:
            _mutate_fingerprint_fields(ev, not is_known, mutation_seed)
        proxy_events.extend(c2_beacon_events)

        logger.info(f"  Attack chain '{chain_id}' injected: user={user['username']}, system={system['hostname']}, "
                    f"classification={'KNOWN' if is_known else 'UNKNOWN'}")

    logger.info(f"[*] Attack injection complete: {known_injected} KNOWN, {unknown_injected} UNKNOWN")

    # ==================================================================
    # PHASE D: Sort each dataset and write separate NDJSON files
    # ==================================================================

    datasets = {
        "auth": auth_events,
        "endpoint": endpoint_events,
        "dns": dns_events,
        "firewall": firewall_events,
        "proxy": proxy_events,
    }

    # Sort each dataset independently by timestamp
    for name, events in datasets.items():
        events.sort(key=lambda e: e.timestamp)

    # Write output
    _write_datasets(datasets, format_type, attack_scenarios)


def _write_datasets(datasets, format_type, attack_scenarios):
    """
    Writes each telemetry dataset to its own NDJSON file and prints per-dataset statistics.
    """
    output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'output'))
    os.makedirs(output_dir, exist_ok=True)
    timestamp_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")

    total_events = 0
    start_time = datetime.now()

    print("\n" + "=" * 70)
    print("  SYNTHETIC TELEMETRY GENERATION — MULTI-SOURCE OUTPUT")
    print("=" * 70)

    for name, events in datasets.items():
        file_name = f"{name}_dataset_{timestamp_prefix}.ndjson"
        file_path = os.path.join(output_dir, file_name)

        type_counts = Counter()
        severity_counts = Counter()
        attack_chain_count = 0

        with open(file_path, "w") as f:
            for event in events:
                f.write(to_json_str(event) + "\n")
                type_counts[event.event_type] += 1
                severity_counts[event.severity] += 1
                if event.correlation and event.correlation.attack_chain_id:
                    attack_chain_count += 1

        total_events += len(events)

        print(f"\n{'─' * 60}")
        print(f"  📄 {file_name}")
        print(f"{'─' * 60}")
        print(f"  Total Events       : {len(events)}")
        print(f"  Attack-Correlated  : {attack_chain_count}")
        print(f"  File               : {file_path}")
        print("  Severity Breakdown :")
        for sev in ["info", "warning", "medium", "high", "critical"]:
            if sev in severity_counts:
                print(f"    {sev:12s} : {severity_counts[sev]}")
        print("  Event Types        :")
        for etype, cnt in type_counts.most_common(8):
            print(f"    {etype:28s} : {cnt}")

    elapsed = (datetime.now() - start_time).total_seconds()

    # Cross-dataset correlation summary
    chain_ids = set()
    for events in datasets.values():
        for ev in events:
            if ev.correlation and ev.correlation.attack_chain_id:
                chain_ids.add(ev.correlation.attack_chain_id)

    print(f"\n{'=' * 70}")
    print("  GENERATION COMPLETE")
    print(f"{'=' * 70}")
    print(f"  Total Events (all sources) : {total_events}")
    print(f"  Total Datasets Written     : {len(datasets)}")
    print(f"  Serialization Time         : {elapsed:.2f}s")
    print(f"  Attack Chains Generated    : {len(attack_scenarios)}")
    print(f"  Unique Chain IDs           : {len(chain_ids)}")
    print(f"  Output Directory           : {os.path.abspath(os.path.join(os.path.dirname(__file__), 'output'))}")

    if chain_ids:
        print("\n  Cross-Dataset Correlation IDs:")
        for cid in sorted(chain_ids):
            sources_with = []
            for name, events in datasets.items():
                if any(e.correlation and e.correlation.attack_chain_id == cid for e in events):
                    sources_with.append(name)
            print(f"    {cid} → [{', '.join(sources_with)}]")

    print(f"{'=' * 70}\n")


# ==============================================================================
# CLI ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enterprise Synthetic Telemetry Generator — Multi-Source SIEM-Compatible Output"
    )
    parser.add_argument("--count", type=int, default=500,
                        help="Approximate number of benign events per telemetry source (default: 500)")
    parser.add_argument("--attacks", type=int, default=3,
                        help="Number of cross-dataset attack chains to inject (default: 3)")
    parser.add_argument("--format", type=str, choices=["ndjson"], default="ndjson",
                        help="Output format (default: ndjson)")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for deterministic generation")
    parser.add_argument("--known-ratio", type=float, default=0.70,
                        help="Proportion of attacks that should be KNOWN (matching fingerprints). "
                             "Default: 0.70 (70%% KNOWN, 30%% UNKNOWN). "
                             "Range: 0.0 to 1.0")
    args = parser.parse_args()

    generate_all_telemetry(args.count, args.attacks, args.format, args.seed, args.known_ratio)
