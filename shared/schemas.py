import uuid
from datetime import datetime, timezone
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict

# ==============================================================================
# SUB-MODELS (NESTED CONTEXTS)
# ==============================================================================


class SourceInfo(BaseModel):
    ip: str = Field(..., description="Source IPv4/IPv6 address")
    port: Optional[int] = Field(None, description="Source port")
    hostname: Optional[str] = Field(None, description="Source hostname if resolved")
    geo: Optional[str] = Field(None, description="Geolocation country/region tag")


class DestinationInfo(BaseModel):
    ip: str = Field(..., description="Destination IPv4/IPv6 address")
    port: Optional[int] = Field(None, description="Destination port")
    hostname: Optional[str] = Field(None, description="Destination hostname")


class UserInfo(BaseModel):
    username: Optional[str] = Field(None, description="Targeted or active username")
    role: Optional[str] = Field(None, description="RBAC role or group")
    department: Optional[str] = Field(None, description="Corporate department context")


class ProcessInfo(BaseModel):
    name: Optional[str] = Field(None, description="Running process name (e.g., sshd, bash)")
    pid: Optional[int] = Field(None, description="Process ID")
    parent_process_name: Optional[str] = Field(None, description="Parent process name")
    command_line: Optional[str] = Field(None, description="Full execution command line")


class FileInfo(BaseModel):
    file_path: Optional[str] = Field(None, description="Absolute path to the file")
    file_name: Optional[str] = Field(None, description="Base name of the file")
    file_hash: Optional[str] = Field(None, description="SHA256 hash of the file if calculated")


class HTTPInfo(BaseModel):
    method: Optional[str] = Field(None, description="HTTP Method (GET, POST, etc.)")
    endpoint: Optional[str] = Field(None, description="URL Path or URI target")
    status_code: Optional[int] = Field(None, description="HTTP response code")


class SystemInfo(BaseModel):
    os: Optional[str] = Field(None, description="Operating system identifier")
    container_id: Optional[str] = Field(None, description="Docker/K8s container ID if applicable")


class DNSInfo(BaseModel):
    queried_domain: Optional[str] = Field(None, description="The domain name queried")
    query_type: Optional[str] = Field(None, description="DNS query type (A, AAAA, TXT, MX, CNAME, etc.)")
    resolved_ip: Optional[str] = Field(None, description="The IP address resolved")
    response_code: Optional[str] = Field(None, description="DNS response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)")
    ttl: Optional[int] = Field(None, description="Time to live in seconds")


class FirewallInfo(BaseModel):
    action: str = Field(..., description="Firewall action (allow, deny, drop, reject)")
    protocol: str = Field("TCP", description="Network protocol (TCP, UDP, ICMP, etc.)")
    bytes_sent: int = Field(0, description="Bytes sent in the session")
    bytes_received: int = Field(0, description="Bytes received in the session")
    session_duration_ms: int = Field(0, description="Session duration in milliseconds")
    rule_id: Optional[str] = Field(None, description="Firewall rule ID that matched")
    direction: str = Field("outbound", description="Traffic direction (inbound, outbound, internal)")


class ProxyInfo(BaseModel):
    url: Optional[str] = Field(None, description="Full request URL")
    method: str = Field("GET", description="HTTP method (GET, POST, PUT, DELETE, CONNECT)")
    status_code: int = Field(200, description="HTTP response status code")
    user_agent: Optional[str] = Field(None, description="Client User-Agent string")
    domain: Optional[str] = Field(None, description="Target domain extracted from URL")
    content_type: Optional[str] = Field(
        None,
        description=("Response content type (e.g., text/html, application/octet-stream)"),
    )
    bytes_transferred: int = Field(0, description="Total bytes transferred")
    referrer: Optional[str] = Field(None, description="HTTP Referer header")
    category: str = Field("uncategorized", description="URL category (business, social, malicious, uncategorized)")


class BehavioralFeatures(BaseModel):
    login_frequency: Optional[int] = Field(None, description="Logins observed within the sliding window")
    failed_attempts: Optional[int] = Field(None, description="Failed attempts within the sliding window")
    time_window_seconds: Optional[int] = Field(None, description="Window size in seconds")
    odd_hour_activity: Optional[bool] = Field(None, description="True if activity occurs outside standard baseline hours")

    # DNS / Network Behavioral Features
    query_frequency: Optional[int] = Field(None, description="Number of DNS queries in rolling window")
    high_entropy_domain: Optional[bool] = Field(None, description="True if domain name has high entropy")
    new_domain_observed: Optional[bool] = Field(None, description="True if domain is newly observed")
    beaconing_detected: Optional[bool] = Field(None, description="True if periodic beaconing pattern is detected")
    ip_classification: Optional[str] = Field(None, description="Categorization of source IP as internal or external")
    is_privileged_user: Optional[bool] = Field(None, description="True if the user is a known privileged user (admin, root)")
    high_frequency: Optional[bool] = Field(None, description="True if high frequency activity is detected")
    sensitive_source_asset: Optional[bool] = Field(None, description="True if the source is considered a sensitive asset")
    sensitive_destination_asset: Optional[bool] = Field(None, description="True if the destination is considered a sensitive asset")


class DetectionInfo(BaseModel):
    signature_match: Optional[bool] = Field(None, description="True if matched via fingerprint Fast Path")
    anomaly_score: Optional[float] = Field(None, description="ML Output: Isolation Forest/LOF outlier score")
    ueba_score: Optional[float] = Field(None, description="ML Output: Behavioral deviation confidence")
    risk_score: Optional[float] = Field(None, description="Fidelity Engine Output: Combined final risk calculation")
    risk_level: Optional[str] = Field(None, description="Categorical risk (low, medium, high, critical)")


class CorrelationInfo(BaseModel):
    attack_chain_id: Optional[str] = Field(None, description="UUID of the correlated multi-stage attack graph")
    session_id: Optional[str] = Field(None, description="User or host interactive session ID")
    parent_event_id: Optional[str] = Field(None, description="Parent event UUID")
    related_events: Optional[List[str]] = Field(None, description="List of related event UUIDs")


class MITREAttackInfo(BaseModel):
    technique_id: Optional[str] = Field(None, description="MITRE Technique ID (e.g., T1110)")
    technique_name: Optional[str] = Field(None, description="MITRE Technique Name")
    tactic: Optional[str] = Field(None, description="MITRE Tactic (e.g., Credential Access)")
    confidence: Optional[float] = Field(None, description="Confidence in this mapping mapping (0.0 - 1.0)")


class PlaybookInfo(BaseModel):
    playbook_id: Optional[str] = Field(None, description="UUID of the generated response playbook")
    generated: Optional[bool] = Field(None, description="True if a playbook has been fully built")
    status: Optional[str] = Field(None, description="Playbook lifecycle status (none, pending, active, completed)")


# ==============================================================================
# MASTER EVENT CONTRACT
# ==============================================================================


class SecurityEvent(BaseModel):
    """
    MASTER EVENT CONTRACT.
    This schema represents the stateful payload of a security incident as it
    traverses the pipeline. It is initialized sparsely and enriched deeply.
    """

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    # Core Identifiers
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique ID for this payload")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event occurrence time (UTC)",
    )
    event_type: str = Field(..., description="High-level category (e.g., failed_login, process_created)")
    severity: str = Field("info", description="Initial rule-based severity from Wazuh")

    # Contextual Blocks
    source: Optional[SourceInfo] = None
    destination: Optional[DestinationInfo] = None
    user: Optional[UserInfo] = None
    process: Optional[ProcessInfo] = None
    file: Optional[FileInfo] = None
    http: Optional[HTTPInfo] = None
    system: Optional[SystemInfo] = None
    dns: Optional[DNSInfo] = None
    firewall: Optional[FirewallInfo] = None
    proxy: Optional[ProxyInfo] = None

    # Analytical State Blocks (Optional - may be None if enrichment stages not yet executed)
    behavioral_features: Optional[BehavioralFeatures] = None
    detection: Optional[DetectionInfo] = None
    correlation: Optional[CorrelationInfo] = None
    mitre_attack: Optional[MITREAttackInfo] = None
    playbook: Optional[PlaybookInfo] = None

    # Immutable Origin
    raw_log: str = Field(
        ...,
        description="The original raw text or JSON string for audit preservation",
    )
