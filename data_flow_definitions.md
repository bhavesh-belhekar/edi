====================================================
🔷 CYBER INCIDENT RESPONSE SYSTEM
🔷 DATA FLOW DEFINITIONS
====================================================

This document defines the COMPLETE movement of data
through the entire AI-powered cyber incident response pipeline.

The goal is to establish:
- standardized data movement,
- module interactions,
- processing responsibilities,
- event transformations,
- system dependencies.

Every module in the architecture must follow this data flow.

====================================================
🔷 GLOBAL PIPELINE OVERVIEW
====================================================

Synthetic Logs / Dummy Banking Applications
        ↓
Wazuh Agents
        ↓
Wazuh Manager
        ↓
OpenSearch
        ↓
Python Ingestion Service
        ↓
Log Enrichment Layer
        ↓
Fingerprint / Signature Matching Engine
        ↓
Known Attack?
   ├── YES → Fetch Existing Incident + Playbook
   └── NO
          ↓
       RabbitMQ Queue
          ↓
    Distributed Worker Pool
          ↓
Preprocessing Layer
          ↓
Feature Extraction Layer
          ↓
Anomaly Detection Engine
          ↓
UEBA Engine
          ↓
Correlation Engine
          ↓
MITRE ATT&CK Mapping Layer
          ↓
Fidelity Ranking Engine
          ↓
PostgreSQL Storage
          ↓
Playbook Generation Engine
          ↓
Ollama LLM Enhancement
          ↓
FastAPI
          ↓
Dashboard / SOC Analyst Interface

====================================================
🔷 DETAILED DATA FLOW DEFINITIONS
====================================================

====================================================
1️⃣ SYNTHETIC LOG GENERATION / DUMMY APPLICATIONS
====================================================

INPUT:
- attack scenario configurations
- user behavior patterns
- system behavior templates

PROCESS:
- generate realistic security logs
- simulate normal user activity
- simulate attack behavior
- simulate banking application activity
- simulate failed login patterns
- simulate privilege escalation
- simulate brute force attacks
- simulate lateral movement

OUTPUT:
- structured JSON logs
- raw simulated security events

OUTPUT DESTINATION:
→ Wazuh Agents

====================================================
2️⃣ WAZUH AGENTS
====================================================

INPUT:
- system logs
- application logs
- container logs
- synthetic security logs

PROCESS:
- collect logs continuously
- monitor host activity
- monitor file changes
- monitor authentication events
- monitor process activity

OUTPUT:
- normalized Wazuh events

OUTPUT DESTINATION:
→ Wazuh Manager

====================================================
3️⃣ WAZUH MANAGER
====================================================

INPUT:
- logs from all Wazuh agents

PROCESS:
- centralized event aggregation
- event normalization
- rule-based alert generation
- metadata attachment

OUTPUT:
- processed Wazuh alerts/events

OUTPUT DESTINATION:
→ OpenSearch

====================================================
4️⃣ OPENSEARCH
====================================================

INPUT:
- Wazuh processed events

PROCESS:
- centralized log storage
- indexing
- event search optimization
- timestamp indexing

OUTPUT:
- searchable indexed events

OUTPUT DESTINATION:
→ Python Ingestion Service

====================================================
5️⃣ PYTHON INGESTION SERVICE
====================================================

INPUT:
- indexed logs from OpenSearch API

PROCESS:
- fetch logs using timestamp filtering
- avoid duplicate ingestion
- normalize event structure
- validate event schema
- convert logs into unified event schema

OUTPUT:
- normalized standardized events

OUTPUT DESTINATION:
→ Log Enrichment Layer

====================================================
6️⃣ LOG ENRICHMENT LAYER
====================================================

INPUT:
- normalized security events

PROCESS:
- IP enrichment
  - internal/external classification
  - geo tagging
  - subnet analysis

- user enrichment
  - role lookup
  - department lookup
  - historical user context

- temporal enrichment
  - odd-hour detection
  - frequency calculations
  - burst behavior detection

- contextual tagging
  - suspicious indicators
  - privilege indicators
  - attack hints

OUTPUT:
- enriched security events

OUTPUT DESTINATION:
→ Fingerprint / Signature Engine

====================================================
7️⃣ FINGERPRINT / SIGNATURE MATCHING ENGINE
====================================================

INPUT:
- enriched security events

PROCESS:
- generate attack fingerprint
- create incident signature
- compare with historical attacks
- similarity matching
- identify repeated attack patterns

DECISION LOGIC:
IF similar attack already exists:
    classify as KNOWN ATTACK
ELSE:
    classify as NEW ATTACK

OUTPUT:
- known attack classification
OR
- new attack classification

OUTPUT DESTINATION:
→ PostgreSQL (known attack)
→ RabbitMQ (new attack)

====================================================
8️⃣ KNOWN ATTACK FLOW
====================================================

INPUT:
- matched historical attack signature

PROCESS:
- retrieve previous incident
- retrieve existing playbook
- retrieve remediation history
- retrieve analyst response

OUTPUT:
- pre-analyzed incident
- recommended existing playbook

OUTPUT DESTINATION:
→ PostgreSQL
→ FastAPI
→ Dashboard

====================================================
9️⃣ RABBITMQ QUEUE
====================================================

INPUT:
- new/unseen attack events

PROCESS:
- asynchronous buffering
- queue distribution
- workload balancing
- decouple ingestion from ML processing

OUTPUT:
- distributed processing tasks

OUTPUT DESTINATION:
→ Worker Pool

====================================================
🔟 DISTRIBUTED WORKER POOL
====================================================

INPUT:
- queued attack events

PROCESS:
- parallel processing
- distributed task execution
- scalable worker orchestration

OUTPUT:
- events sent to ML pipeline

OUTPUT DESTINATION:
→ Preprocessing Layer

====================================================
1️⃣1️⃣ PREPROCESSING LAYER
====================================================

INPUT:
- enriched security events

PROCESS:
- remove invalid values
- normalize numerical features
- encode categorical fields
- handle missing values
- standardize timestamps
- prepare ML-ready data

OUTPUT:
- cleaned structured ML-ready events

OUTPUT DESTINATION:
→ Feature Extraction Layer

====================================================
1️⃣2️⃣ FEATURE EXTRACTION LAYER
====================================================

INPUT:
- cleaned events

PROCESS:
- extract behavioral features
- time-series analysis
- frequency calculations
- session behavior extraction
- event sequence analysis
- tsfresh feature generation

OUTPUT:
- feature vectors

OUTPUT DESTINATION:
→ Anomaly Detection Engine

====================================================
1️⃣3️⃣ ANOMALY DETECTION ENGINE
====================================================

INPUT:
- feature vectors

PROCESS:
- anomaly inference
- Isolation Forest
- Local Outlier Factor
- Autoencoder models
- outlier scoring

OUTPUT:
- anomaly scores
- anomaly labels

OUTPUT DESTINATION:
→ UEBA Engine
→ Correlation Engine

====================================================
1️⃣4️⃣ UEBA ENGINE
====================================================

INPUT:
- anomaly results
- historical user activity
- entity behavior history

PROCESS:
- user baseline generation
- deviation analysis
- unusual activity detection
- peer comparison
- behavior scoring

OUTPUT:
- UEBA confidence scores

OUTPUT DESTINATION:
→ Correlation Engine

====================================================
1️⃣5️⃣ CORRELATION ENGINE
====================================================

INPUT:
- anomaly results
- UEBA scores
- related events

PROCESS:
- graph construction
- attack chain linking
- multi-stage attack detection
- temporal relationship analysis
- NetworkX graph traversal

OUTPUT:
- correlated incidents
- attack chains

OUTPUT DESTINATION:
→ MITRE ATT&CK Mapping Layer

====================================================
1️⃣6️⃣ MITRE ATT&CK MAPPING LAYER
====================================================

INPUT:
- correlated incidents
- attack chains

PROCESS:
- map behaviors to MITRE techniques
- identify tactics
- assign confidence levels
- enrich threat intelligence context

OUTPUT:
- MITRE ATT&CK enriched incidents

OUTPUT DESTINATION:
→ Fidelity Ranking Engine

====================================================
1️⃣7️⃣ FIDELITY RANKING ENGINE
====================================================

INPUT:
- anomaly score
- UEBA score
- correlation confidence
- MITRE confidence

PROCESS:
- weighted risk scoring
- confidence aggregation
- false-positive reduction
- severity classification

OUTPUT:
- final incident risk score
- incident priority

OUTPUT DESTINATION:
→ PostgreSQL

====================================================
1️⃣8️⃣ POSTGRESQL STORAGE
====================================================

INPUT:
- final incidents
- scores
- signatures
- playbooks
- MITRE mappings

PROCESS:
- persistent storage
- incident history maintenance
- attack signature storage
- audit logging

OUTPUT:
- centralized incident database

OUTPUT DESTINATION:
→ Playbook Engine
→ FastAPI

====================================================
1️⃣9️⃣ PLAYBOOK GENERATION ENGINE
====================================================

INPUT:
- finalized incident
- MITRE mapping
- risk classification

PROCESS:
- generate remediation steps
- generate containment procedures
- generate analyst recommendations
- generate SOC response workflow

OUTPUT:
- incident response playbook

OUTPUT DESTINATION:
→ Ollama Enhancement Layer

====================================================
2️⃣0️⃣ OLLAMA LLM ENHANCEMENT
====================================================

INPUT:
- generated playbook
- incident summary

PROCESS:
- improve readability
- generate analyst explanations
- summarize attack behavior
- produce human-readable SOC guidance

OUTPUT:
- AI-enhanced incident report

OUTPUT DESTINATION:
→ FastAPI

====================================================
2️⃣1️⃣ FASTAPI
====================================================

INPUT:
- incidents
- playbooks
- risk scores
- reports

PROCESS:
- expose REST APIs
- serve dashboard data
- provide incident endpoints
- provide analytics endpoints

OUTPUT:
- API responses

OUTPUT DESTINATION:
→ Dashboard / SOC UI

====================================================
2️⃣2️⃣ DASHBOARD / SOC ANALYST INTERFACE
====================================================

INPUT:
- API responses

PROCESS:
- visualize alerts
- display attack chains
- show MITRE mappings
- display risk scores
- display generated playbooks

OUTPUT:
- analyst visibility
- incident investigation interface

====================================================
🔷 FINAL ENGINEERING PRINCIPLES
====================================================

1. Every module must follow the unified event schema

2. Every module must have clearly defined:
   INPUT → PROCESS → OUTPUT

3. No module should directly depend on UI/frontend

4. Processing must remain asynchronous wherever possible

5. All services should be independently containerized

6. Shared utilities/configurations must remain centralized

7. The architecture must remain fully offline and local

====================================================
END OF DATA FLOW DEFINITIONS
====================================================