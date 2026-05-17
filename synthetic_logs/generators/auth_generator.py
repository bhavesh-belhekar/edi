import json
import random
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from faker import Faker
from shared.schemas import (
    SecurityEvent, SourceInfo, DestinationInfo, UserInfo,
    ProcessInfo, SystemInfo, BehavioralFeatures, DetectionInfo, MITREAttackInfo, CorrelationInfo
)

class AuthEventGenerator:
    """
    Enterprise-grade Synthetic Authentication Event Generator.
    Maintains user state, contextual boundaries, and strict schema validation
    to feed AI/ML security pipelines training data.
    """

    def __init__(self, template_dir: str = "synthetic_logs/templates"):
        self.fake = Faker()

        # Load environment context
        with open(f"{template_dir}/users.json", "r") as f:
            self.users = json.load(f)
        with open(f"{template_dir}/systems.json", "r") as f:
            self.systems = json.load(f)
        with open(f"{template_dir}/ips.json", "r") as f:
            self.ips = json.load(f)

        # Stateful Tracking for UEBA/Correlation logic
        # format: {"username": {"active_sessions": int, "recent_failures": int, "last_ip": str}}
        self.user_state: Dict[str, Dict[str, Any]] = {
            u["username"]: {"active_sessions": 0, "recent_failures": 0, "last_ip": ""}
            for u in self.users
        }

    # ==============================================================================
    # UTILITY METHODS
    # ==============================================================================

    def _create_base_event(self, event_type: str, severity: str, timestamp: datetime) -> SecurityEvent:
        """Centralized Pydantic initialization to enforce schema."""
        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            raw_log="Placeholder"
        )

    def _get_random_ip(self, pool_type: str = "internal_subnets") -> str:
        """Constructs realistic IP boundaries based on role."""
        if pool_type == "known_malicious_ips":
            return random.choice(self.ips["known_malicious_ips"])
        base_subnet = random.choice(self.ips[pool_type])
        return f"{base_subnet}{random.randint(10, 250)}"

    def _is_odd_hour(self, user: Dict, timestamp: datetime) -> bool:
        """Determines if the event violates the template's standard working hours."""
        if user["office_hours_start"] > user["office_hours_end"]: # Over-midnight shift
             return not (user["office_hours_start"] <= timestamp.hour or timestamp.hour <= user["office_hours_end"])
        return not (user["office_hours_start"] <= timestamp.hour <= user["office_hours_end"])

    # ==============================================================================
    # 1. NORMAL AUTH EVENTS
    # ==============================================================================

    def generate_successful_login(self, timestamp: datetime, user: Optional[Dict] = None) -> SecurityEvent:
        user = user or random.choice(self.users)
        system = random.choice(self.systems)

        # Pick IP logic based on role
        ip_pool = "vpn_pool" if user.get("is_admin") and random.random() > 0.5 else "internal_subnets"
        src_ip = self._get_random_ip(ip_pool)

        odd_hour = self._is_odd_hour(user, timestamp)

        # State update
        self.user_state[user["username"]]["active_sessions"] += 1
        self.user_state[user["username"]]["recent_failures"] = 0 # reset on success
        self.user_state[user["username"]]["last_ip"] = src_ip

        event = self._create_base_event("successful_login", "info", timestamp)

        event.source = SourceInfo(ip=src_ip, hostname=f"ws-{user['username']}")
        event.destination = DestinationInfo(ip=system["ip"], port=22, hostname=system["hostname"])
        event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
        event.process = ProcessInfo(name="sshd", pid=random.randint(1000, 9999))
        event.system = SystemInfo(os=system["os"])

        # Consistent Behavioral Baseline
        event.behavioral_features = BehavioralFeatures(
            login_frequency=self.user_state[user["username"]]["active_sessions"],
            failed_attempts=0,
            odd_hour_activity=odd_hour
        )

        session_id = f"sess_{uuid.uuid4().hex[:8]}"
        self.user_state[user["username"]]["current_session"] = session_id

        event.correlation = CorrelationInfo(session_id=session_id)

        if odd_hour or "vpn_pool" in ip_pool:
            event.detection = DetectionInfo(anomaly_score=random.uniform(0.1, 0.4), ueba_score=0.4, risk_score=20.0, risk_level="low")
        else:
            event.detection = DetectionInfo(anomaly_score=random.uniform(0.01, 0.05), ueba_score=0.01, risk_score=0.0, risk_level="low")

        event.mitre_attack = MITREAttackInfo(technique_id="T1078", technique_name="Valid Accounts", tactic="Initial Access", confidence=0.8)

        event.raw_log = f"sshd: Accepted publickey for {user['username']} from {src_ip} port {random.randint(10000,60000)} ssh2"
        return event

    def generate_logout(self, timestamp: datetime, user: Optional[Dict] = None) -> SecurityEvent:
        user = user or random.choice(self.users)

        # State update (prevent negative sessions)
        if self.user_state[user["username"]]["active_sessions"] > 0:
            self.user_state[user["username"]]["active_sessions"] -= 1

        event = self._create_base_event("logout", "info", timestamp)
        event.source = SourceInfo(ip=self.user_state[user["username"]]["last_ip"] or self._get_random_ip())
        event.user = UserInfo(username=user["username"], role=user["role"])
        event.raw_log = f"sshd: session closed for user {user['username']}"
        return event

    # ==============================================================================
    # 2. SUSPICIOUS AUTH EVENTS
    # ==============================================================================

    def generate_failed_login(self, timestamp: datetime, user: Optional[Dict] = None, attacker_ip: str = None) -> SecurityEvent:
        user = user or random.choice(self.users)
        system = random.choice(self.systems)
        src_ip = attacker_ip or self._get_random_ip("internal_subnets")

        # State update
        self.user_state[user["username"]]["recent_failures"] += 1
        current_failures = self.user_state[user["username"]]["recent_failures"]

        severity = "warning" if current_failures < 3 else "high"

        event = self._create_base_event("failed_login", severity, timestamp)
        event.source = SourceInfo(ip=src_ip)
        event.destination = DestinationInfo(ip=system["ip"], port=22, hostname=system["hostname"])
        event.user = UserInfo(username=user["username"])

        event.behavioral_features = BehavioralFeatures(
            login_frequency=self.user_state[user["username"]]["active_sessions"],
            failed_attempts=current_failures,
            odd_hour_activity=self._is_odd_hour(user, timestamp)
        )

        event.detection = DetectionInfo(anomaly_score=min(0.1 * current_failures, 0.95), ueba_score=min(0.2 * current_failures, 0.9), risk_score=min(10.0 * current_failures, 95.0), risk_level=severity)
        event.mitre_attack = MITREAttackInfo(technique_id="T1110", technique_name="Brute Force", tactic="Credential Access", confidence=0.85)

        event.raw_log = f"sshd: Failed password for {user['username']} from {src_ip} port {random.randint(10000,60000)}"
        return event

    def generate_brute_force_attack(self, start_time: datetime, count: int = 15) -> List[SecurityEvent]:
        """
        Generates a tightly coupled cluster of failed logins from a malicious IP,
        potentially ending in a successful compromise.
        """
        events = []
        target_user = random.choice(self.users)
        attacker_ip = self._get_random_ip("known_malicious_ips")

        current_time = start_time

        for i in range(count):
            # Attackers script hitting 1-2 seconds apart
            current_time += timedelta(seconds=random.randint(1, 2))

            # Add failed event
            failed_event = self.generate_failed_login(current_time, target_user, attacker_ip=attacker_ip)
            events.append(failed_event)

        # 10% chance the brute force succeeds
        if random.random() < 0.10:
            current_time += timedelta(seconds=random.randint(1, 2))
            success_event = self.generate_successful_login(current_time, target_user)
            success_event.source.ip = attacker_ip # Override to malicious IP
            success_event.source.geo = "External-Malicious"
            success_event.severity = "critical"
            events.append(success_event)

        return events

    def generate_admin_after_hours(self, timestamp: datetime) -> SecurityEvent:
        """Force highly suspicious temporal access by a privileged account."""
        admin_user = random.choice([u for u in self.users if u.get("is_admin")])
        if not admin_user:
            return None # Failsafe

        # Force the hour outside standard bounds
        hours_to_avoid = list(range(admin_user["office_hours_start"], admin_user["office_hours_end"] + 1))
        possible_bad_hours = [h for h in range(24) if h not in hours_to_avoid]

        if not possible_bad_hours:
            # If the user works 24/7 (e.g. service account), arbitrarily force a generally
            # suspicious time like 3 AM to flag as odd/anomaly purely by mathematical baseline
            bad_hour = 3
        else:
            bad_hour = random.choice(possible_bad_hours)

        bad_time = timestamp.replace(hour=bad_hour, minute=random.randint(0, 59))

        event = self.generate_successful_login(bad_time, admin_user)
        event.severity = "medium"
        event.behavioral_features.odd_hour_activity = True
        return event

    def generate_unusual_ip_login(self, timestamp: datetime) -> SecurityEvent:
        """Valid user logs in successfully, but from a known malicious botnet/VPS IP."""
        user = random.choice(self.users)
        bad_ip = self._get_random_ip("known_malicious_ips")

        event = self.generate_successful_login(timestamp, user)
        event.source.ip = bad_ip
        event.source.geo = "Suspicious-ASN"
        event.severity = "high"
        event.raw_log = f"sshd: Accepted password for {user['username']} from unusual/blacklisted {bad_ip}"
        return event

