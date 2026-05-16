import json
import math
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
    Simulates internal routing, browsing, typo-squatting, DGA lookups,
    DNS tunneling exfiltration, and C2 beaconing with UEBA correlation.
    """

    def __init__(self, template_dir: str = "synthetic_logs/templates"):
        self.fake = Faker()
        with open(f"{template_dir}/users.json", "r") as f:
            self.users = json.load(f)
        with open(f"{template_dir}/systems.json", "r") as f:
            self.systems = json.load(f)
        with open(f"{template_dir}/ips.json", "r") as f:
            self.ips = json.load(f)

        self.benign_domains = [
            "microsoft.com", "github.com", "office365.com", "login.microsoftonline.com",
            "google.com", "googleapis.com", "slack.com", "salesforce.com",
            "zoom.us", "teams.microsoft.com", "dropbox.com", "box.com",
            "cdn.jsdelivr.net", "cloudflare.com", "akamaihd.net", "fastly.net",
            "aws.amazon.com", "s3.amazonaws.com", "azure.microsoft.com",
            "ubuntu.com", "pypi.org", "npmjs.com", "stackoverflow.com",
            "internal-api.corp.local", "jira.corp.local", "confluence.corp.local",
            "gitlab.corp.local", "ldap.corp.local", "mail.corp.local",
            "reuters.com", "bbc.com", "linkedin.com", "wikipedia.org",
        ]
        self.malicious_domains = [
            "micr0soft.com", "mircosoft-update.com", "login-office365-secure.net",
            "xj3k91-malware-c2.xyz", "data-sync-ddns.biz", "mimi-k-toolkit.xyz",
            "powershell-gallery-dl.info", "update-kb4013429.info",
            "secure-banklogin.com", "paypal-verify-account.net",
            "dynamic-resolve-01.duckdns.org", "node-proxy-88.no-ip.biz",
            "pastebin-downloads.ru", "file-share-cdn.tk", "temp-storage.cc",
        ]
        self.typosquat_map = {
            "microsoft.com": ["micr0soft.com", "mircosoft.com", "microsft.com"],
            "github.com": ["g1thub.com", "githb.com", "githubb.com"],
            "google.com": ["gooogle.com", "gogle.com", "g00gle.com"],
            "slack.com": ["slakc.com", "slcak.com", "s1ack.com"],
            "dropbox.com": ["drobox.com", "dr0pbox.com", "dropbx.com"],
            "office365.com": ["0ffice365.com", "officee365.com", "office356.com"],
        }
        self.dns_resolver_ip = "10.0.1.2"

    def _create_base_event(self, event_type, severity, timestamp):
        return SecurityEvent(
            event_id=str(uuid.uuid4()), timestamp=timestamp,
            event_type=event_type, severity=severity, raw_log="Placeholder"
        )

    def _get_user_info(self, user):
        return UserInfo(username=user['username'], role=user['role'], department=user['department'])

    def _calculate_entropy(self, domain):
        if not domain:
            return 0.0
        prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    # ==========================================================================
    # 1. BENIGN DNS EVENTS
    # ==========================================================================
    def generate_benign_dns(self, timestamp, user, system):
        events = []
        count = random.randint(2, 6)
        current_time = timestamp
        session_id = f"sess_{random.randint(10000, 99999)}"
        for _ in range(count):
            current_time += timedelta(milliseconds=random.randint(10, 500))
            event = self._create_base_event("dns_query", "info", current_time)
            event.user = self._get_user_info(user)
            domain = random.choice(self.benign_domains)
            q_type = random.choices(["A", "AAAA", "TXT", "CNAME", "MX"], weights=[0.65, 0.10, 0.05, 0.12, 0.08])[0]
            if random.random() < 0.3 and not domain.endswith(".local"):
                domain = f"{self.fake.word()}.{domain}"
            is_internal = domain.endswith(".local")
            event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"],
                                       geo="Internal-Corporate" if "10." in system["ip"] else "Remote-VPN")
            resolved = f"10.0.1.{random.randint(10, 200)}" if is_internal else self.fake.ipv4()
            resp_code = "NOERROR" if random.random() < 0.95 else "NXDOMAIN"
            event.dns = DNSInfo(queried_domain=domain, query_type=q_type, resolved_ip=resolved,
                                response_code=resp_code, ttl=random.randint(60, 86400))
            event.behavioral_features = BehavioralFeatures(query_frequency=random.randint(5, 50))
            event.detection = DetectionInfo(anomaly_score=random.uniform(0.0, 0.05), ueba_score=0.01, risk_score=0.0, risk_level="low")
            event.correlation = CorrelationInfo(session_id=session_id)
            event.raw_log = f"named[{random.randint(1000,9999)}]: client {system['ip']}#{random.randint(30000,65000)} ({domain}): query: {domain} IN {q_type} + ({self.dns_resolver_ip})"
            events.append(event)
        return events

    # ==========================================================================
    # 2. TYPO-SQUATTING DNS QUERIES
    # ==========================================================================
    def generate_typosquat_query(self, timestamp, user, system):
        legit_domain = random.choice(list(self.typosquat_map.keys()))
        typo_domain = random.choice(self.typosquat_map[legit_domain])
        event = self._create_base_event("dns_query", "warning", timestamp)
        event.user = self._get_user_info(user)
        event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        event.dns = DNSInfo(queried_domain=typo_domain, query_type="A", resolved_ip=self.fake.ipv4(),
                            response_code="NOERROR", ttl=random.randint(30, 300))
        event.behavioral_features = BehavioralFeatures(query_frequency=random.randint(10, 30), new_domain_observed=True)
        event.detection = DetectionInfo(anomaly_score=random.uniform(0.35, 0.55), ueba_score=random.uniform(0.30, 0.50),
                                         risk_score=random.uniform(25.0, 45.0), risk_level="medium")
        event.mitre_attack = MITREAttackInfo(technique_id="T1568", technique_name="Dynamic Resolution",
                                              tactic="Command and Control", confidence=0.65)
        event.raw_log = f"RPZ_Alert: DNS query to suspected typo-squatted domain {typo_domain} (similar to {legit_domain}) from {system['hostname']} ({system['ip']}). User: {user['username']}"
        return event

    # ==========================================================================
    # 3. DGA (DOMAIN GENERATION ALGORITHM) QUERIES
    # ==========================================================================
    def generate_dga_query(self, timestamp, user, system, attack_chain_id=None, prev_event_id=None):
        events = []
        current_time = timestamp
        session_id = f"sess_{uuid.uuid4().hex[:8]}"
        tlds = [".xyz", ".top", ".info", ".biz", ".cc", ".tk", ".ru"]
        for i in range(random.randint(4, 8)):
            current_time += timedelta(milliseconds=random.randint(50, 300))
            length = random.randint(12, 24)
            random_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
            dga_domain = f"{random_label}{random.choice(tlds)}"
            event = self._create_base_event("dns_query", "high", current_time)
            event.user = self._get_user_info(user)
            event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
            resp_code = "NOERROR" if random.random() < 0.15 else "NXDOMAIN"
            resolved = self.fake.ipv4() if resp_code == "NOERROR" else None
            event.dns = DNSInfo(queried_domain=dga_domain, query_type="A", resolved_ip=resolved,
                                response_code=resp_code, ttl=random.randint(5, 30) if resp_code == "NOERROR" else None)
            entropy = self._calculate_entropy(random_label)
            event.behavioral_features = BehavioralFeatures(query_frequency=random.randint(80, 400),
                                                            high_entropy_domain=True, new_domain_observed=True, beaconing_detected=i > 2)
            event.detection = DetectionInfo(anomaly_score=random.uniform(0.80, 0.96), ueba_score=random.uniform(0.75, 0.92),
                                             risk_score=random.uniform(70.0, 90.0), risk_level="high", signature_match=entropy > 3.5)
            event.mitre_attack = MITREAttackInfo(technique_id="T1568.002", technique_name="Dynamic Resolution: Domain Generation Algorithms",
                                                  tactic="Command and Control", confidence=0.88)
            event.correlation = CorrelationInfo(attack_chain_id=attack_chain_id, session_id=session_id,
                                                 related_events=[prev_event_id] if prev_event_id else [])
            event.raw_log = f"DNS_Anomaly: High-entropy domain query. Domain: {dga_domain} (entropy={entropy:.2f}) from {system['hostname']} ({system['ip']}). Response: {resp_code}. Query #{i+1}."
            events.append(event)
            prev_event_id = event.event_id
        return events

    # ==========================================================================
    # 4. DNS TUNNELING / EXFILTRATION
    # ==========================================================================
    def generate_dns_tunneling(self, timestamp, user, system, attack_chain_id=None, prev_event_id=None):
        events = []
        current_time = timestamp
        session_id = f"sess_{uuid.uuid4().hex[:8]}"
        tunnel_domain = random.choice(["data-sync-ddns.biz", "xj3k91-malware-c2.xyz", "temp-storage.cc"])
        for i in range(random.randint(3, 6)):
            current_time += timedelta(seconds=random.randint(1, 5))
            encoded_payload = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(30, 63)))
            query_domain = f"{encoded_payload}.{tunnel_domain}"
            event = self._create_base_event("dns_query", "critical", current_time)
            event.user = self._get_user_info(user)
            event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
            event.dns = DNSInfo(queried_domain=query_domain, query_type="TXT", resolved_ip=self.fake.ipv4(),
                                response_code="NOERROR", ttl=random.randint(5, 15))
            event.behavioral_features = BehavioralFeatures(query_frequency=random.randint(200, 800),
                                                            high_entropy_domain=True, new_domain_observed=True, beaconing_detected=True)
            event.detection = DetectionInfo(anomaly_score=random.uniform(0.92, 0.99), ueba_score=random.uniform(0.90, 0.98),
                                             risk_score=random.uniform(90.0, 100.0), risk_level="critical", signature_match=True)
            event.mitre_attack = MITREAttackInfo(technique_id="T1071.004", technique_name="Application Layer Protocol: DNS",
                                                  tactic="Exfiltration", confidence=0.95)
            event.correlation = CorrelationInfo(attack_chain_id=attack_chain_id, session_id=session_id,
                                                 related_events=[prev_event_id] if prev_event_id else [])
            event.raw_log = f"DNS_EXFIL_ALERT: Suspected DNS tunneling. Oversized TXT query ({len(query_domain)} chars) to {tunnel_domain} from {system['hostname']} ({system['ip']}). Payload length: {len(encoded_payload)}."
            events.append(event)
            prev_event_id = event.event_id
        return events

    # ==========================================================================
    # 5. MALICIOUS C2 BEACONING
    # ==========================================================================
    def generate_malicious_beacon(self, start_time, target_user, system, attack_chain_id, prev_event_id=None):
        events = []
        current_time = start_time
        malicious_domain = random.choice(self.malicious_domains)
        session_id = f"sess_{uuid.uuid4().hex[:8]}"
        is_dga = random.random() < 0.5
        for i in range(random.randint(3, 5)):
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
            event.dns = DNSInfo(queried_domain=query_domain, query_type=q_type, resolved_ip=self.fake.ipv4(),
                                response_code="NOERROR", ttl=random.randint(10, 60))
            event.behavioral_features = BehavioralFeatures(query_frequency=random.randint(100, 500),
                                                            high_entropy_domain=is_dga, new_domain_observed=True, beaconing_detected=True)
            event.mitre_attack = MITREAttackInfo(technique_id="T1071.004", technique_name="Application Layer Protocol: DNS",
                                                  tactic="Command and Control", confidence=0.92)
            event.detection = DetectionInfo(anomaly_score=random.uniform(0.85, 0.98), ueba_score=0.90,
                                             risk_score=85.0, risk_level="high", signature_match=True)
            event.correlation = CorrelationInfo(attack_chain_id=attack_chain_id,
                                                 related_events=[prev_event_id] if prev_event_id else [], session_id=session_id)
            tag = "high-entropy beaconing" if is_dga else "suspicious dynamic DNS"
            event.raw_log = f"DNS_Beacon: {tag} toward {query_domain} from {system['hostname']} ({system['ip']}). Beacon #{i+1}."
            events.append(event)
            prev_event_id = event.event_id
        return events