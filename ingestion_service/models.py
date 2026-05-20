"""Pydantic models for normalized ingestion records and checkpoint state."""

from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class NullableSourceInfo(BaseModel):
    """Source connection details."""

    model_config = ConfigDict(extra="ignore")

    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    geo: Optional[str] = None


class NullableDestinationInfo(BaseModel):
    """Destination connection details."""

    model_config = ConfigDict(extra="ignore")

    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    geo: Optional[str] = None


class NullableUserInfo(BaseModel):
    """User context."""

    model_config = ConfigDict(extra="ignore")

    username: Optional[str] = None
    role: Optional[str] = None
    department: Optional[str] = None


class NullableProcessInfo(BaseModel):
    """Process context."""

    model_config = ConfigDict(extra="ignore")

    name: Optional[str] = None
    pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None


class NullableFileInfo(BaseModel):
    """File context."""

    model_config = ConfigDict(extra="ignore")

    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_hash: Optional[str] = None


class NullableHTTPInfo(BaseModel):
    """HTTP context."""

    model_config = ConfigDict(extra="ignore")

    method: Optional[str] = None
    endpoint: Optional[str] = None
    status_code: Optional[int] = None


class NullableSystemInfo(BaseModel):
    """System context."""

    model_config = ConfigDict(extra="ignore")

    os: Optional[str] = None
    container_id: Optional[str] = None


class NullableDNSInfo(BaseModel):
    """DNS context."""

    model_config = ConfigDict(extra="ignore")

    queried_domain: Optional[str] = None
    query_type: Optional[str] = None
    resolved_ip: Optional[str] = None
    response_code: Optional[str] = None
    ttl: Optional[int] = None


class NullableFirewallInfo(BaseModel):
    """Firewall context."""

    model_config = ConfigDict(extra="ignore")

    action: Optional[str] = None
    protocol: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    session_duration_ms: Optional[int] = None
    rule_id: Optional[str] = None
    direction: Optional[str] = None


class NullableProxyInfo(BaseModel):
    """Proxy context."""

    model_config = ConfigDict(extra="ignore")

    url: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    domain: Optional[str] = None
    content_type: Optional[str] = None
    bytes_transferred: Optional[int] = None
    referrer: Optional[str] = None
    category: Optional[str] = None


class NullableBehavioralFeatures(BaseModel):
    """Behavioral context."""

    model_config = ConfigDict(extra="ignore")

    login_frequency: Optional[int] = None
    failed_attempts: Optional[int] = None
    time_window_seconds: Optional[int] = None
    odd_hour_activity: Optional[bool] = None
    query_frequency: Optional[int] = None
    high_entropy_domain: Optional[bool] = None
    new_domain_observed: Optional[bool] = None
    beaconing_detected: Optional[bool] = None
    ip_classification: Optional[str] = None
    is_privileged_user: Optional[bool] = None
    high_frequency: Optional[bool] = None
    sensitive_source_asset: Optional[bool] = None
    sensitive_destination_asset: Optional[bool] = None


class NullableDetectionInfo(BaseModel):
    """Detection and scoring context."""

    model_config = ConfigDict(extra="ignore")

    signature_match: Optional[bool] = None
    anomaly_score: Optional[float] = None
    ueba_score: Optional[float] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None


class NullableCorrelationInfo(BaseModel):
    """Correlation context."""

    model_config = ConfigDict(extra="ignore")

    attack_chain_id: Optional[str] = None
    session_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    related_events: Optional[List[str]] = None


class NullableMitreAttackInfo(BaseModel):
    """MITRE ATT&CK context."""

    model_config = ConfigDict(extra="ignore")

    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    confidence: Optional[float] = None


class NullablePlaybookInfo(BaseModel):
    """Playbook context."""

    model_config = ConfigDict(extra="ignore")

    playbook_id: Optional[str] = None
    generated: Optional[bool] = None
    status: Optional[str] = None


class NormalizedEvent(BaseModel):
    """Normalized event written to local NDJSON storage."""

    model_config = ConfigDict(extra="ignore")

    event_id: str
    timestamp: datetime
    event_type: str
    severity: Optional[str] = None

    source: Optional[NullableSourceInfo] = None
    destination: Optional[NullableDestinationInfo] = None
    user: Optional[NullableUserInfo] = None
    process: Optional[NullableProcessInfo] = None
    file: Optional[NullableFileInfo] = None
    http: Optional[NullableHTTPInfo] = None
    system: Optional[NullableSystemInfo] = None
    dns: Optional[NullableDNSInfo] = None
    firewall: Optional[NullableFirewallInfo] = None
    proxy: Optional[NullableProxyInfo] = None

    behavioral_features: Optional[NullableBehavioralFeatures] = None
    detection: Optional[NullableDetectionInfo] = None
    correlation: Optional[NullableCorrelationInfo] = None
    mitre_attack: Optional[NullableMitreAttackInfo] = None
    playbook: Optional[NullablePlaybookInfo] = None

    raw_log: Optional[str] = None


class IngestionCheckpoint(BaseModel):
    """Persistent checkpoint used to resume incremental polling."""

    model_config = ConfigDict(extra="ignore")

    last_timestamp: Optional[str] = None
    last_sort: Optional[List[Any]] = None
    processed_ids: List[str] = Field(default_factory=list)
