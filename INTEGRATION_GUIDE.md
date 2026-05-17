# 🚀 Enrichment & Signature Engine Pipeline Integration Guide

## Overview

This document describes the complete integration of **Module 5 (Log Enrichment Engine)** and **Module 6 (Signature/Fingerprint Engine)** into the ingestion service pipeline.

### Architecture

```
Wazuh Alerts (OpenSearch)
      ↓
[Ingestion Service]
  • Fetch with checkpoint
  • Normalize to SecurityEvent schema
      ↓
[MODULE 5: ENRICHMENT ENGINE]
  • IP classification (internal/external)
  • User role/department tagging
  • Odd-hour activity detection
  • Context-based severity escalation
      ↓
[MODULE 6: SIGNATURE/FINGERPRINT ENGINE]
  • Generate SHA-256 fingerprint
  • Lookup against 11 known patterns
      ↓
DECISION LOGIC:
  • KNOWN ATTACK → PostgreSQL (fast-path)
  • NEW ATTACK → RabbitMQ (ML workers)
```

---

## Deployment

### 1. Checkout Integration Branch

```bash
git checkout fix/integrate-enrichment-pipeline
```

### 2. Start Docker Compose Stack

```bash
# Pull latest images
docker-compose pull

# Build and start
docker-compose up -d

# Verify all services are running
docker-compose ps
```

### 3. Verify Service Health

```bash
# Check ingestion service logs
docker logs -f ingestion_service

# Expected output:
# INFO:ingestion.service:Starting Ingestion Service with Enrichment & Signature Pipeline...
# INFO:ingestion.service:Connected to OpenSearch: 8.5.0
# INFO:ingestion.service:Connected to PostgreSQL: incidents
# INFO:ingestion.service:Connected to RabbitMQ: rabbitmq:5672
# INFO:signature.store:seeded 11 known attack patterns
```

---

## Event Flow Examples

### Example 1: Known Attack (Brute Force)

**Raw Wazuh Alert:**
```json
{
  "id": "EVT-001",
  "timestamp": "2026-05-17T22:15:30Z",
  "rule": {
    "description": "failed login",
    "level": 12
  },
  "data": {
    "srcip": "203.0.113.50",
    "srcport": 54321,
    "dstip": "192.168.1.100",
    "dstport": 22,
    "user": "admin",
    "failed_attempts": 15,
    "login_frequency": 20
  }
}
```

**After Normalization:**
```python
SecurityEvent(
  event_id="EVT-001",
  event_type="failed_login",
  severity="high",
  source=SourceInfo(ip="203.0.113.50", port=54321),
  destination=DestinationInfo(ip="192.168.1.100", port=22),
  user_username="admin",
  behavioral_features=BehavioralFeatures(
    failed_attempts=15,
    login_frequency=20
  )
)
```

**After Enrichment (Module 5):**
```python
# IP enricher
event.source.geo = "external"  # 203.0.113.50 is external

# User enricher
event.user.role = "administrator"
event.extra['is_privileged'] = True

# Time enricher (22:15 = 10:15 PM)
event.behavioral_features.odd_hour_activity = True

# Context tagger
# Risk signals: 4 (suspicious_type=True, repeated=True, high_freq=True, odd_hour=True)
# Escalate to HIGH → already HIGH, stays HIGH
risk_signals = 4
```

**After Fingerprinting (Module 6):**
```python
fingerprint = SHA256(
  "failed_login|external|high|odd_hour|repeated_failures|high_frequency"
)
# fingerprint = "a4f8e2c19d5b42e3..."  (first 11 seeded patterns)
```

**Match Result:**
```python
MatchResult(
  classification=AttackClassification.KNOWN,
  fingerprint="a4f8e2c19d5b42e3",
  event={
    event.detection.signature_match = True
    event.detection.risk_score = 0.95
    event.detection.risk_level = "critical"
    event.mitre_attack.technique_id = "T1110"
    event.mitre_attack.technique_name = "Brute Force"
    event.mitre_attack.tactic = "Credential Access"
    event.playbook.playbook_id = "PB-BRUTE-001"
  }
)
```

**Routing Decision: KNOWN ATTACK**
- Store to PostgreSQL with MITRE mapping
- Skip ML/UEBA pipeline (fast-path)
- Ready for immediate response

---

### Example 2: New Attack (Anomaly)

**Raw Wazuh Alert:**
```json
{
  "id": "EVT-002",
  "timestamp": "2026-05-17T23:45:00Z",
  "rule": {
    "description": "suspicious api call",
    "level": 8
  },
  "data": {
    "srcip": "10.0.0.50",
    "srcport": 56789,
    "dstip": "203.0.113.200",
    "dstport": 443,
    "user": "service_account",
    "failed_attempts": 0,
    "login_frequency": 1
  }
}
```

**After Enrichment:**
```python
# IP enricher: source is internal (10.0.0.0/8), destination is external
# User enricher: role=standard_user, not privileged
# Time enricher: 23:45 is off-hours → odd_hour_activity=True
# Context tagger: risk_signals=2 (suspicious_type + odd_hour) → severity="medium"
```

**After Fingerprinting:**
```python
fingerprint = SHA256("suspicious_api_call|external|medium|odd_hour")
# No match in store (this is a NEW pattern)
```

**Match Result:**
```python
MatchResult(
  classification=AttackClassification.NEW,
  fingerprint="c7b3a2e9d1f4...",
  event=event  # Enriched but NOT classified as known
)
```

**Routing Decision: NEW ATTACK**
- Serialize to JSON
- Publish to RabbitMQ queue `ml_pipeline`
- ML workers consume and perform:
  - Anomaly detection
  - UEBA analysis
  - Correlation
  - MITRE mapping
  - Fidelity ranking
- Results written to PostgreSQL after processing

---

## Configuration

### Environment Variables

**OpenSearch:**
```bash
OPENSEARCH_HOST=wazuh.indexer
OPENSEARCH_PORT=9200
OPENSEARCH_USERNAME=admin
OPENSEARCH_PASSWORD=admin
OPENSEARCH_INDEX_PATTERN=wazuh-alerts-*
```

**Polling:**
```bash
POLL_INTERVAL_SECONDS=5        # Check for new events every 5 seconds
BATCH_SIZE=200                 # Fetch up to 200 events per poll
REQUEST_TIMEOUT_SECONDS=30     # OpenSearch request timeout
```

**Checkpoint:**
```bash
CHECKPOINT_PATH=/app/state/checkpoint.json
OUTPUT_PATH=/app/logs/normalized_events.ndjson
```

**PostgreSQL:**
```bash
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin
POSTGRES_DB=incidents
```

**RabbitMQ:**
```bash
RABBITMQ_HOST=rabbitmq
RABBITMQ_PORT=5672
RABBITMQ_USER=guest
RABBITMQ_PASSWORD=guest
RABBITMQ_QUEUE=ml_pipeline
```

---

## Monitoring & Troubleshooting

### Check Service Status

```bash
# View running containers
docker-compose ps

# Expected:
# NAME                    STATUS
# ingestion_service       Up (healthy)
# postgres_db             Up (healthy)
# rabbitmq_broker         Up (healthy)
# wazuh.indexer           Up (healthy)
```

### View Logs

```bash
# Ingestion service
docker logs -f ingestion_service

# PostgreSQL
docker logs -f postgres_db

# RabbitMQ
docker logs -f rabbitmq_broker
```

### Query PostgreSQL

```bash
# Connect to PostgreSQL
docker exec -it postgres_db psql -U admin -d incidents

# View incidents table
SELECT * FROM incidents LIMIT 5;

# Count by event type
SELECT event_type, COUNT(*) FROM incidents GROUP BY event_type;
```

### Query RabbitMQ

```bash
# Access RabbitMQ Management UI
# http://localhost:15672
# Username: guest
# Password: guest

# Or via CLI:
docker exec -it rabbitmq_broker rabbitmqctl list_queues
```

### Common Issues

**Issue: "Connection refused" for PostgreSQL**
- Ensure `postgres` service is healthy: `docker-compose ps`
- Check logs: `docker logs postgres_db`
- Verify environment variables match: `POSTGRES_HOST=postgres`

**Issue: "Connection refused" for RabbitMQ**
- Ensure `rabbitmq` service is healthy
- Check that port 5672 is not blocked
- Verify credentials: `RABBITMQ_USER=guest, RABBITMQ_PASSWORD=guest`

**Issue: No events being processed**
- Verify Wazuh alerts exist in OpenSearch: `curl http://localhost:9200/wazuh-alerts-*/_count`
- Check checkpoint file: `cat ingestion_service/state/checkpoint.json`
- Verify poll interval: `POLL_INTERVAL_SECONDS` (default 5 seconds)

**Issue: Events stuck in RabbitMQ queue**
- Verify ML workers are consuming (Module 7+ not yet implemented)
- Manually consume for testing:
  ```python
  import pika
  conn = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
  channel = conn.channel()
  channel.queue_declare(queue='ml_pipeline', durable=True)
  def callback(ch, method, properties, body):
      print(f"Received: {body}")
      ch.basic_ack(delivery_tag=method.delivery_tag)
  channel.basic_consume(queue='ml_pipeline', on_message_callback=callback)
  channel.start_consuming()
  ```

---

## Testing

### Test Script: Full Pipeline End-to-End

```python
# test_pipeline.py
from src.services.enrichment_engine import enrich_event
from src.services.signature_engine import match_event, SignatureStore
from shared.schemas import SecurityEvent, SourceInfo, DestinationInfo, BehavioralFeatures
from datetime import datetime

# Create a test event
event = SecurityEvent(
    event_id="TEST-001",
    timestamp=datetime.utcnow(),
    event_type="failed_login",
    severity="medium",
    source=SourceInfo(ip="203.0.113.50", port=443),
    destination=DestinationInfo(ip="192.168.1.1", port=22),
    user_username="admin",
    raw_log='{"test": true}',
    behavioral_features=BehavioralFeatures(
        failed_attempts=10,
        login_frequency=15
    )
)

# Run enrichment
print("\n[ENRICHMENT]")
enriched = enrich_event(event)
print(f"Source Geo: {enriched.source.geo}")
print(f"User Role: {enriched.user.role if enriched.user else 'N/A'}")
print(f"Odd Hour: {enriched.behavioral_features.odd_hour_activity}")
print(f"Severity After: {enriched.severity}")

# Run signature matching
print("\n[SIGNATURE MATCHING]")
store = SignatureStore()
store.seed_known_patterns()
result = match_event(enriched, store)

print(f"Classification: {result.classification}")
print(f"Fingerprint: {result.fingerprint[:16]}")
if result.event.mitre_attack:
    print(f"MITRE Technique: {result.event.mitre_attack.technique_id}")
if result.event.playbook:
    print(f"Playbook ID: {result.event.playbook.playbook_id}")

print("\n✅ Pipeline test complete!")
```

**Run:**
```bash
python test_pipeline.py
```

---

## Next Steps

1. **Verify Pipeline is Running**
   - Check logs: `docker logs -f ingestion_service`
   - Confirm events being enriched and routed

2. **Implement Module 7 (ML Workers)**
   - Create workers that consume RabbitMQ queue
   - Process new attacks with anomaly detection + UEBA

3. **Setup PostgreSQL Tables** (if not auto-created)
   ```sql
   CREATE TABLE incidents (
     id SERIAL PRIMARY KEY,
     event_id VARCHAR(255) UNIQUE,
     event_type VARCHAR(100),
     severity VARCHAR(20),
     source_ip INET,
     dest_ip INET,
     signature_id VARCHAR(16),
     mitre_technique VARCHAR(20),
     risk_score FLOAT,
     timestamp TIMESTAMP,
     raw_event JSONB,
     created_at TIMESTAMP DEFAULT NOW()
   );
   ```

4. **Monitor Metrics**
   - Known attacks per hour
   - New attacks per hour
   - RabbitMQ queue depth
   - Processing latency

---

## Architecture Decision Records

### Why In-Memory Signature Store?
- **Fast matching** for 11 seeded patterns (microseconds)
- **PostgreSQL backing** not yet wired (Module 12)
- **Scalable to disk** once DB layer ready

### Why RabbitMQ for New Attacks?
- **Decouples** ingestion from ML processing
- **Enables async** processing without blocking
- **Distributes** load across multiple workers
- **Provides durability** (persisted if workers crash)

### Why Fast-Path for Known Attacks?
- **Reduces latency** from minutes → milliseconds
- **Skips expensive** ML/UEBA for repeated patterns
- **Enables immediate** response with pre-computed playbooks
- **MITRE mapping already done** at fingerprint registration

---

## Summary

✅ **Complete Pipeline Integration:**
- Module 5 (Enrichment) fully operational
- Module 6 (Signature/Fingerprint) fully operational
- Known attacks routed to PostgreSQL (fast-path)
- New attacks queued for ML processing
- All services containerized and orchestrated

**Status:** Ready for deployment 🚀
