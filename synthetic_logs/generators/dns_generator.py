import json
import random
import uuid
import string
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from faker import Faker
from shared.schemas import (
    SecurityEvent, SourceInfo, UserInfo, 
    DNSInfo, BehavioralFeatures, DetectionInfo, MITREAttackInfo, CorrelationInfo
)

class DNSEventGenerator:
    """
    Enterprise DNS Telemetry Generator.
    Simulates internal standard routing, employee browsing, typo-squatting interactions,
    and malicious C2 beaconing with UEBA and SIEM correlation features.
    """

    def __init__(self, template_dir: str = "synthetic_logs/templates"):
        self.fake = Faker()
        
        # Load environment context
        with open(f"{template_dir}/users.json", "r") as f:
            self.users = json.load(f)
        with open(f"{template_dir}/systems.json", "r") as f:
            self.systems = json.load(f)
            
        self.benign_domains = [
            "microsoft.com", "github.com", "ubuntu.com", "office365.com", 
            "internal-api.corp.local", "jira.corp.local", "aws.amazon.com", 
            "google.com", "slack.com", "salesforce.com"
        ]
        
        self.malicious_domains = [
            "update-microsoft-security.com", "login-office365-secure.net", 
            "xj3k91-malware-c2.xyz", "pastebin-downloads.ru", "data-sync-ddns.biz",
            "mimi-k-toolkit.xyz", "powershell-gallery-dl.info"
        ]

    def _create_base_event(self, event_type: str, severity: str, timestamp: datetime) -> SecurityEvent:
        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            raw_log="Placeholder"
        )
        
    def _get_user_info(self, user: Dict) -> UserInfo:
        return UserInfo(username=user['username'], role=user['role'], department=user['department'])

    # ==============================================================================
    # 1. BENIGN DNS EVENTS
    # ==============================================================================

    def generate_benign_dns(self, timestamp: datetime, user: Dict, system: Dict) -> List[SecurityEvent]:
        """Generates realistic normal corporate DNS lookups."""
        events = []
        count = random.randint(2, 6) # Web browsing generates many DNS requests
        current_time = timestamp
        session_id = f"sess_{random.randint(10000, 99999)}"
        
        for _ in range(count):
            current_time += timedelta(milliseconds=random.randint(10, 500))
            event = self._create_base_event("dns_query", "low", current_time)
            
            event.user = self._get_user_info(user)
            # Add DNS specific properties
            domain = random.choice(self.benign_domains)
            q_type = random.choices(["A", "AAAA", "TXT", "CNAME"], weights=[0.7, 0.1, 0.05, 0.15])[0]
            
            # Subdomain generation for reality
            if random.random() < 0.3 and not domain.endswith(".local"):
                 domain = f"{self.fake.word()}.{domain}"
            
            event.source = SourceInfo(
                ip=system["ip"], 
                hostname=system["hostname"],
                geo="Internal-Corporate" if "10." in system["ip"] else "Remote-VPN"
            )
            
            event.dns = DNSInfo(
                queried_domain=domain,
                query_type=q_type,
                resolved_ip=self.fake.ipv4() if not domain.endswith(".local") else f"10.0.1.{random.randint(10, 200)}",
                response_code="NOERROR" if random.random() < 0.95 else "NXDOMAIN",
                ttl=random.randint(30, 3600)
            )
            
            event.behavioral_features = BehavioralFeatures(query_frequency=random.randint(5, 50))
            event.detection = DetectionInfo(anomaly_score=random.uniform(0.0, 0.05), risk_score=0.0, risk_level="low")
            event.correlation = CorrelationInfo(session_id=session_id)
            
            event.raw_log = f"DNS query by {system['hostname']} ({system['ip']}) for {event.dns.queried_domain} type {event.dns.query_type}. Response: {event.dns.response_code}."
            events.append(event)
            
        return events

    # ==============================================================================
    # 2. MALICIOUS / ATTACK CHAIN DNS EVENTS (BEACONING & EXFIL)
    # ==============================================================================

    def generate_malicious_beacon(self, start_time: datetime, target_user: Dict, system: Dict, attack_chain_id: str, prev_event_id: str) -> List[SecurityEvent]:
        """
        Generates simulated malware C2 beaconing. Integrates with Endpoint powershell/malware chains.
        """
        events = []
        current_time = start_time
        malicious_domain = random.choice(self.malicious_domains)
        session_id = f"sess_{uuid.uuid4().hex[:8]}"
        
        # High entropy random subdomains (e.g. DNS tunneling / DGA)
        is_dga = random.random() < 0.5
        
        # Simulate 3-5 rapid beacon pulses
        for _ in range(random.randint(3, 5)):
            current_time += timedelta(seconds=random.randint(2, 10))
            event = self._create_base_event("dns_query", "high", current_time)
            
            event.user = self._get_user_info(target_user)
            event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
            
            if is_dga:
                random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
                query_domain = f"{random_sub}.{malicious_domain}"
            else:
                query_domain = malicious_domain
                
            q_type = random.choices(["A", "TXT"], weights=[0.8, 0.2])[0]
            
            event.dns = DNSInfo(
                queried_domain=query_domain,
                query_type=q_type,
                resolved_ip=self.fake.ipv4(),
                response_code="NOERROR",
                ttl=random.randint(10, 60) # Fast flux TTL
            )
            
            event.behavioral_features = BehavioralFeatures(
                query_frequency=random.randint(100, 500),
                high_entropy_domain=is_dga,
                new_domain_observed=True,
                beaconing_detected=True
            )
            
            event.mitre_attack = MITREAttackInfo(
                technique_id="T1071.004", 
                technique_name="Application Layer Protocol: DNS", 
                tactic="Command and Control", 
                confidence=0.92
            )
            
            event.detection = DetectionInfo(
                anomaly_score=random.uniform(0.85, 0.98), 
                ueba_score=0.90, 
                risk_score=85.0, 
                risk_level="high",
                signature_match=True
            )
            
            event.correlation = CorrelationInfo(
                attack_chain_id=attack_chain_id, 
                related_events=[prev_event_id] if prev_event_id else [],
                session_id=session_id
            )
            
            if is_dga:
                event.raw_log = f"Repeated high-entropy beaconing activity observed toward {query_domain} from {system['hostname']}."
            else:
                event.raw_log = f"DNS query to suspicious dynamic DNS domain detected from {system['hostname']} ({system['ip']}). Domain: {query_domain}"
                
            events.append(event)
            prev_event_id = event.event_id # Chain next beacon
            
        return events