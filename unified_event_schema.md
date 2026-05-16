# Unified Event Schema

This document defines the central data contract for the autonomous AI-powered Cyber Incident Response System. All logs ingested into the system are normalized into this strict schema before being passed down the pipeline (Signature Engine, RabbitMQ, ML Workers, Postgres).

## JSON Payload Example

This is exactly how a structured event looks as it moves through the processing pipeline. It acts as a **stateful payload**, being enriched as it passes through each microservice.

```json
{
  "event_id": "uuid-string",
  "timestamp": "2026-05-15T10:20:00Z",
  "event_type": "failed_login",
  "severity": "medium",
  "source": {
    "ip": "192.168.1.50",
    "port": 443,
    "hostname": "client-machine",
    "geo": "internal"
  },
  "destination": {
    "ip": "10.0.0.5",
    "port": 22,
    "hostname": "bank-server-1"
  },
  "user": {
    "username": "admin",
    "role": "administrator",
    "department": "IT"
  },
  "process": {
    "name": "ssh",
    "pid": 1234
  },
  "http": {
    "method": "POST",
    "endpoint": "/login",
    "status_code": 401
  },
  "system": {
    "os": "Ubuntu 22.04",
    "container_id": "abc123"
  },
  "behavioral_features": {
    "login_frequency": 15,
    "failed_attempts": 10,
    "time_window_seconds": 60,
    "odd_hour_activity": true
  },
  "detection": {
    "signature_match": false,
    "anomaly_score": 0.91,
    "ueba_score": 0.88,
    "risk_score": 0.95,
    "risk_level": "high"
  },
  "correlation": {
    "attack_chain_id": "chain-001",
    "related_events": [
      "event-101",
      "event-102"
    ]
  },
  "mitre_attack": {
    "technique_id": "T1110",
    "technique_name": "Brute Force",
    "tactic": "Credential Access",
    "confidence": 0.92
  },
  "playbook": {
    "playbook_id": "PB-001",
    "generated": true,
    "status": "pending"
  },
  "raw_log": "Original raw log text"
}
```

## Python Pydantic Implementation

To enforce this schema across the Python microservices (FastAPI, RabbitMQ consumers, Data Ingestion), we use Pydantic models. This ensures strict validation, typing support, and automated OpenAPI documentation generation.

```python
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class Entity(BaseModel):
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None
    geo: Optional[str] = None

class User(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
    department: Optional[str] = None

class ProcessContext(BaseModel):
    name: Optional[str] = None
    pid: Optional[int] = None

class HttpContext(BaseModel):
    method: Optional[str] = None
    endpoint: Optional[str] = None
    status_code: Optional[int] = None

class SystemContext(BaseModel):
    os: Optional[str] = None
    container_id: Optional[str] = None

class BehavioralFeatures(BaseModel):
    login_frequency: Optional[int] = 0
    failed_attempts: Optional[int] = 0
    time_window_seconds: Optional[int] = 60
    odd_hour_activity: Optional[bool] = False

class DetectionScores(BaseModel):
    signature_match: bool = False
    anomaly_score: float = 0.0
    ueba_score: float = 0.0
    risk_score: float = 0.0
    risk_level: str = "low"  # low, medium, high, critical

class CorrelationState(BaseModel):
    attack_chain_id: Optional[str] = None
    related_events: List[str] = Field(default_factory=list)

class MitreContext(BaseModel):
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    confidence: float = 0.0

class PlaybookState(BaseModel):
    playbook_id: Optional[str] = None
    generated: bool = False
    status: str = "none" # none, pending, completed

class UnifiedEvent(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    
    source: Optional[Entity] = None
    destination: Optional[Entity] = None
    user: Optional[User] = None
    process: Optional[ProcessContext] = None
    http: Optional[HttpContext] = None
    system: Optional[SystemContext] = None
    
    behavioral_features: BehavioralFeatures = Field(default_factory=BehavioralFeatures)
    detection: DetectionScores = Field(default_factory=DetectionScores)
    correlation: CorrelationState = Field(default_factory=CorrelationState)
    mitre_attack: MitreContext = Field(default_factory=MitreContext)
    playbook: PlaybookState = Field(default_factory=PlaybookState)
    
    raw_log: str
```
