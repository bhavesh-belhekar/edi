import json
import random
import uuid
from datetime import timedelta

from faker import Faker
from shared.schemas import (
    SecurityEvent, SourceInfo, DestinationInfo, UserInfo, SystemInfo,
    FirewallInfo, DetectionInfo, MITREAttackInfo, CorrelationInfo
)


class FirewallEventGenerator:
    """
    Enterprise Perimeter Firewall Telemetry Generator.
    Simulates allowed/denied traffic, lateral movement, C2 outbound connections,
    and data exfiltration events with SIEM-compatible raw_log formatting.
    """

    def __init__(self, template_dir: str = "synthetic_logs/templates"):
        self.fake = Faker()
        with open(f"{template_dir}/users.json", "r") as f:
            self.users = json.load(f)
        with open(f"{template_dir}/systems.json", "r") as f:
            self.systems = json.load(f)
        with open(f"{template_dir}/ips.json", "r") as f:
            self.ips = json.load(f)

        self.common_ports = {
            "web": [80, 443, 8080, 8443],
            "email": [25, 465, 587, 993, 995],
            "dns": [53],
            "ssh": [22],
            "smb": [445, 139],
            "rdp": [3389],
            "db": [3306, 5432, 1433, 27017],
        }
        self.suspicious_ports = [4444, 1337, 8888, 9001, 31337, 6667, 6697, 5555, 12345]
        self.lateral_ports = [445, 135, 139, 3389, 5985, 5986, 22]

    def _create_base_event(self, event_type, severity, timestamp):
        return SecurityEvent(
            event_id=str(uuid.uuid4()), timestamp=timestamp,
            event_type=event_type, severity=severity, raw_log="Placeholder"
        )

    def _get_random_external_ip(self):
        return self.fake.ipv4_public()

    def _get_random_internal_ip(self):
        base = random.choice(self.ips["internal_subnets"])
        return f"{base}{random.randint(10, 250)}"

    def _get_malicious_ip(self):
        return random.choice(self.ips["known_malicious_ips"])

    def _get_system_by_ip(self, ip):
        for s in self.systems:
            if s["ip"] == ip:
                return s
        return None

    # ==========================================================================
    # 1. NORMAL OUTBOUND TRAFFIC
    # ==========================================================================
    def generate_normal_outbound(self, timestamp, user, system):
        events = []
        count = random.randint(1, 4)
        current_time = timestamp
        session_id = f"sess_{random.randint(10000, 99999)}"
        for _ in range(count):
            current_time += timedelta(seconds=random.randint(1, 30))
            event = self._create_base_event("firewall_allow", "info", current_time)
            dst_ip = self._get_random_external_ip()
            dst_port = random.choice(self.common_ports["web"])
            proto = "TCP"
            bytes_s = random.randint(200, 15000)
            bytes_r = random.randint(500, 50000)
            duration = random.randint(100, 30000)

            event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
            event.destination = DestinationInfo(ip=dst_ip, port=dst_port)
            event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
            event.system = SystemInfo(os=system["os"])
            event.firewall = FirewallInfo(
                action="allow", protocol=proto, bytes_sent=bytes_s, bytes_received=bytes_r,
                session_duration_ms=duration, rule_id=f"RULE-{random.randint(100,999)}",
                direction="outbound"
            )
            event.detection = DetectionInfo(anomaly_score=random.uniform(0.0, 0.05), ueba_score=0.01,
                                             risk_score=0.0, risk_level="low")
            event.correlation = CorrelationInfo(session_id=session_id)
            event.raw_log = (
                f"FW: {current_time.isoformat()} action=allow proto={proto} "
                f"src={system['ip']} dst={dst_ip} dport={dst_port} "
                f"sent={bytes_s} rcvd={bytes_r} duration={duration}ms "
                f"rule=ALLOW-OUTBOUND-WEB user={user['username']}"
            )
            events.append(event)
        return events

    # ==========================================================================
    # 2. NORMAL INTERNAL (EAST-WEST) TRAFFIC
    # ==========================================================================
    def generate_normal_internal(self, timestamp, user, system):
        event = self._create_base_event("firewall_allow", "info", timestamp)
        dst_ip = self._get_random_internal_ip()
        dst_port = random.choice([22, 445, 3306, 5432, 8080])
        proto = "TCP"
        bytes_s = random.randint(100, 5000)
        bytes_r = random.randint(100, 10000)

        event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        event.destination = DestinationInfo(ip=dst_ip, port=dst_port)
        event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
        event.system = SystemInfo(os=system["os"])
        event.firewall = FirewallInfo(
            action="allow", protocol=proto, bytes_sent=bytes_s, bytes_received=bytes_r,
            session_duration_ms=random.randint(50, 5000),
            rule_id=f"RULE-{random.randint(200,399)}", direction="internal"
        )
        event.detection = DetectionInfo(anomaly_score=random.uniform(0.0, 0.03), ueba_score=0.01,
                                         risk_score=0.0, risk_level="low")
        event.correlation = CorrelationInfo(session_id=f"sess_{random.randint(10000, 99999)}")
        event.raw_log = (
            f"FW: {timestamp.isoformat()} action=allow proto={proto} "
            f"src={system['ip']} dst={dst_ip} dport={dst_port} "
            f"sent={bytes_s} rcvd={bytes_r} direction=internal "
            f"rule=ALLOW-INTERNAL user={user['username']}"
        )
        return event

    # ==========================================================================
    # 3. DENIED TRAFFIC (port scans, unauthorized services)
    # ==========================================================================
    def generate_denied_traffic(self, timestamp, user, system):
        event = self._create_base_event("firewall_deny", "warning", timestamp)
        is_external = random.random() < 0.6
        if is_external:
            src_ip = self._get_random_external_ip()
            dst_ip = system["ip"]
            direction = "inbound"
        else:
            src_ip = system["ip"]
            dst_ip = self._get_random_external_ip()
            direction = "outbound"

        dst_port = random.choice(self.suspicious_ports + [23, 21, 8888, 161])
        proto = random.choice(["TCP", "UDP"])

        event.source = SourceInfo(ip=src_ip, hostname=system["hostname"] if not is_external else None)
        event.destination = DestinationInfo(ip=dst_ip, port=dst_port)
        event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
        event.firewall = FirewallInfo(
            action="deny", protocol=proto, bytes_sent=random.randint(40, 200), bytes_received=0,
            session_duration_ms=0, rule_id=f"RULE-DENY-{random.randint(500,699)}", direction=direction
        )
        event.detection = DetectionInfo(
            anomaly_score=random.uniform(0.20, 0.45), ueba_score=random.uniform(0.15, 0.35),
            risk_score=random.uniform(15.0, 35.0), risk_level="medium"
        )
        event.mitre_attack = MITREAttackInfo(
            technique_id="T1046", technique_name="Network Service Scanning",
            tactic="Discovery", confidence=0.60
        )
        event.raw_log = (
            f"FW: {timestamp.isoformat()} action=deny proto={proto} "
            f"src={src_ip} dst={dst_ip} dport={dst_port} "
            f"direction={direction} rule=DENY-POLICY "
            f"reason=unauthorized_port user={user['username']}"
        )
        return event

    # ==========================================================================
    # 4. LATERAL MOVEMENT TRAFFIC
    # ==========================================================================
    def generate_lateral_movement(self, timestamp, user, system, attack_chain_id=None, prev_event_id=None):
        events = []
        current_time = timestamp
        session_id = f"sess_{uuid.uuid4().hex[:8]}"
        targets = [s for s in self.systems if s["ip"] != system["ip"]]
        hop_count = random.randint(2, 4)

        for i in range(min(hop_count, len(targets))):
            current_time += timedelta(seconds=random.randint(3, 15))
            target = targets[i]
            dst_port = random.choice(self.lateral_ports)
            event = self._create_base_event("firewall_allow", "high", current_time)
            event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
            event.destination = DestinationInfo(ip=target["ip"], port=dst_port, hostname=target["hostname"])
            event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
            event.system = SystemInfo(os=system["os"])
            event.firewall = FirewallInfo(
                action="allow", protocol="TCP",
                bytes_sent=random.randint(500, 8000), bytes_received=random.randint(200, 5000),
                session_duration_ms=random.randint(1000, 15000),
                rule_id=f"RULE-{random.randint(300,499)}", direction="internal"
            )
            event.detection = DetectionInfo(
                anomaly_score=random.uniform(0.60, 0.82), ueba_score=random.uniform(0.55, 0.78),
                risk_score=random.uniform(55.0, 80.0), risk_level="high"
            )
            event.mitre_attack = MITREAttackInfo(
                technique_id="T1021", technique_name="Remote Services",
                tactic="Lateral Movement", confidence=0.80
            )
            event.correlation = CorrelationInfo(
                attack_chain_id=attack_chain_id, session_id=session_id,
                related_events=[prev_event_id] if prev_event_id else []
            )
            svc_name = {445: "SMB", 135: "RPC", 3389: "RDP", 5985: "WinRM", 22: "SSH"}.get(dst_port, "unknown")
            event.raw_log = (
                f"FW_LATERAL: {current_time.isoformat()} action=allow proto=TCP "
                f"src={system['ip']} dst={target['ip']} dport={dst_port} "
                f"service={svc_name} direction=internal "
                f"alert=lateral_movement_detected user={user['username']} "
                f"hop={i+1}/{hop_count}"
            )
            events.append(event)
            prev_event_id = event.event_id
        return events

    # ==========================================================================
    # 5. C2 OUTBOUND CONNECTION
    # ==========================================================================
    def generate_c2_outbound(self, timestamp, user, system, attack_chain_id=None, prev_event_id=None):
        event = self._create_base_event("firewall_allow", "critical", timestamp)
        c2_ip = self._get_malicious_ip()
        c2_port = random.choice(self.suspicious_ports)

        event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        event.destination = DestinationInfo(ip=c2_ip, port=c2_port)
        event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
        event.system = SystemInfo(os=system["os"])
        event.firewall = FirewallInfo(
            action="allow", protocol="TCP",
            bytes_sent=random.randint(1000, 25000), bytes_received=random.randint(500, 15000),
            session_duration_ms=random.randint(5000, 120000),
            rule_id=f"RULE-{random.randint(100,199)}", direction="outbound"
        )
        event.detection = DetectionInfo(
            anomaly_score=random.uniform(0.88, 0.99), ueba_score=random.uniform(0.85, 0.98),
            risk_score=random.uniform(85.0, 100.0), risk_level="critical", signature_match=True
        )
        event.mitre_attack = MITREAttackInfo(
            technique_id="T1071", technique_name="Application Layer Protocol",
            tactic="Command and Control", confidence=0.93
        )
        event.correlation = CorrelationInfo(
            attack_chain_id=attack_chain_id,
            session_id=f"sess_{uuid.uuid4().hex[:8]}",
            related_events=[prev_event_id] if prev_event_id else []
        )
        event.raw_log = (
            f"FW_C2_ALERT: {timestamp.isoformat()} action=allow proto=TCP "
            f"src={system['ip']} dst={c2_ip} dport={c2_port} "
            f"direction=outbound alert=c2_connection "
            f"threat_intel=known_malicious_ip duration={event.firewall.session_duration_ms}ms "
            f"user={user['username']}"
        )
        return event

    # ==========================================================================
    # 6. DATA EXFILTRATION (large outbound transfer)
    # ==========================================================================
    def generate_data_exfil(self, timestamp, user, system, attack_chain_id=None, prev_event_id=None):
        event = self._create_base_event("firewall_allow", "critical", timestamp)
        exfil_ip = self._get_malicious_ip()
        exfil_port = random.choice([443, 8443, 53, 80])
        bytes_out = random.randint(50_000_000, 500_000_000)  # 50MB - 500MB

        event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        event.destination = DestinationInfo(ip=exfil_ip, port=exfil_port)
        event.user = UserInfo(username=user["username"], role=user["role"], department=user["department"])
        event.system = SystemInfo(os=system["os"])
        event.firewall = FirewallInfo(
            action="allow", protocol="TCP",
            bytes_sent=bytes_out, bytes_received=random.randint(1000, 10000),
            session_duration_ms=random.randint(30000, 600000),
            rule_id=f"RULE-{random.randint(100,199)}", direction="outbound"
        )
        event.detection = DetectionInfo(
            anomaly_score=random.uniform(0.90, 0.99), ueba_score=random.uniform(0.88, 0.97),
            risk_score=random.uniform(90.0, 100.0), risk_level="critical", signature_match=True
        )
        event.mitre_attack = MITREAttackInfo(
            technique_id="T1048", technique_name="Exfiltration Over Alternative Protocol",
            tactic="Exfiltration", confidence=0.90
        )
        event.correlation = CorrelationInfo(
            attack_chain_id=attack_chain_id,
            session_id=f"sess_{uuid.uuid4().hex[:8]}",
            related_events=[prev_event_id] if prev_event_id else []
        )
        mb_sent = bytes_out / (1024 * 1024)
        event.raw_log = (
            f"FW_EXFIL_ALERT: {timestamp.isoformat()} action=allow proto=TCP "
            f"src={system['ip']} dst={exfil_ip} dport={exfil_port} "
            f"sent={bytes_out} ({mb_sent:.1f}MB) direction=outbound "
            f"alert=abnormal_data_volume threat_intel=known_malicious_ip "
            f"user={user['username']}"
        )
        return event
