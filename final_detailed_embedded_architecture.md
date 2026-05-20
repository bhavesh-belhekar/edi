# 🧠🔥 FINAL EMBEDDED SYSTEM ARCHITECTURE
## Autonomous AI-Driven Cyber Incident Response Platform
*(Offline • Dockerized • MITRE-Aware • UEBA-Based • Scalable)*

---

# 🔷 COMPLETE ARCHITECTURE WITH EMBEDDED MODULE DETAILS

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                            HOST MACHINE                                     │
│                        (Ubuntu / Linux Server)                              │
│                                                                              │
│ ┌──────────────────────────────────────────────────────────────────────────┐ │
│ │                    DOCKER COMPOSE NETWORK                               │ │
│ │                                                                          │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ 1. LOG GENERATION LAYER                                             │ │ │
│ │ │----------------------------------------------------------------------│ │ │
│ │ │ Sources:                                                             │ │ │
│ │ │  • Synthetic Logs (Phase 1)                                          │ │ │
│ │ │  • Dummy Banking Application Containers (Phase 2)                    │ │ │
│ │ │  • Authentication Services                                           │ │ │
│ │ │  • Database Activity Logs                                            │ │ │
│ │ │  • Attacker Containers / Scripts                                     │ │ │
│ │ │                                                                      │ │ │
│ │ │ Internal Work:                                                       │ │ │
│ │ │  • Generate failed login events                                      │ │ │
│ │ │  • Generate brute force patterns                                     │ │ │
│ │ │  • Generate suspicious API requests                                  │ │ │
│ │ │  • Generate privilege escalation attempts                            │ │ │
│ │ │                                                                      │ │ │
│ │ │ Tech Stack:                                                          │ │ │
│ │ │  • Python                                                            │ │ │
│ │ │  • Flask / FastAPI                                                   │ │ │
│ │ │  • Docker Containers                                                 │ │ │
│ │ └──────────────────────────────┬───────────────────────────────────────┘ │ │
│ │                                ▼                                         │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ 2. WAZUH AGENT + MANAGER                                            │ │ │
│ │ │----------------------------------------------------------------------│ │ │
│ │ │ Internal Work:                                                       │ │ │
│ │ │  • Monitor system/application log files                              │ │ │
│ │ │  • Collect endpoint security events                                  │ │ │
│ │ │  • Parse logs into structured events                                 │ │ │
│ │ │  • Apply initial rule-based detection                                │ │ │
│ │ │                                                                      │ │ │
│ │ │ Example Monitored Files:                                             │ │ │
│ │ │  • /var/log/auth.log                                                 │ │ │
│ │ │  • Application API logs                                              │ │ │
│ │ │                                                                      │ │ │
│ │ │ Tech Stack:                                                          │ │ │
│ │ │  • Wazuh Agent                                                       │ │ │
│ │ │  • Wazuh Manager                                                     │ │ │
│ │ └──────────────────────────────┬───────────────────────────────────────┘ │ │
│ │                                ▼                                         │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ 3. OPENSEARCH CONTAINER                                              │ │ │
│ │ │----------------------------------------------------------------------│ │ │
│ │ │ Purpose: Central searchable log storage                              │ │ │
│ │ │                                                                      │ │ │
│ │ │ Internal Work:                                                       │ │ │
│ │ │  • Store logs in indexed format                                      │ │ │
│ │ │  • Enable fast querying                                              │ │ │
│ │ │  • Maintain timestamp-based storage                                  │ │ │
│ │ │  • Act as centralized event lake                                     │ │ │
│ │ │                                                                      │ │ │
│ │ │ Tech Stack:                                                          │ │ │
│ │ │  • OpenSearch                                                        │ │ │
│ │ └──────────────────────────────┬───────────────────────────────────────┘ │ │
│ │                                ▼                                         │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ 4. PYTHON INGESTION SERVICE CONTAINER                               │ │ │
│ │ │----------------------------------------------------------------------│ │ │
│ │ │ Internal Work:                                                       │ │ │
│ │ │  • Fetch only NEW logs using timestamp filtering                     │ │ │
│ │ │  • Normalize inconsistent log formats                                │ │ │
│ │ │  • Convert logs into standard JSON schema                            │ │ │
│ │ │  • Remove duplicate events                                           │ │ │
│ │ │                                                                      │ │ │
│ │ │ Example Query Logic:                                                 │ │ │
│ │ │  timestamp > last_fetched_timestamp                                  │ │ │
│ │ │                                                                      │ │ │
│ │ │ Tech Stack:                                                          │ │ │
│ │ │  • Python                                                            │ │ │
│ │ │  • opensearch-py                                                     │ │ │
│ │ └──────────────────────────────┬───────────────────────────────────────┘ │ │
│ │                                ▼                                         │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ 5. LOG ENRICHMENT ENGINE                                             │ │ │
│ │ │----------------------------------------------------------------------│ │ │
│ │ │ Internal Work:                                                       │ │ │
│ │ │  • IP enrichment (internal/external classification)                  │ │ │
│ │ │  • User enrichment (role/history analysis)                           │ │ │
│ │ │  • Time enrichment (odd-hour activity detection)                     │ │ │
│ │ │  • Context tagging (suspicious patterns)                             │ │ │
│ │ │                                                                      │ │ │
│ │ │ Added Context Example:                                               │ │ │
│ │ │  • suspicious_time = true                                            │ │ │
│ │ │  • repeated_attempt = true                                           │ │ │
│ │ │                                                                      │ │ │
│ │ │ Tech Stack:                                                          │ │ │
│ │ │  • Python                                                            │ │ │
│ │ │  • pandas                                                            │ │ │
│ │ └──────────────────────────────┬───────────────────────────────────────┘ │ │
│ │                                ▼                                         │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ 6. SIGNATURE / FINGERPRINT ENGINE                                    │ │ │
│ │ │----------------------------------------------------------------------│ │ │
│ │ │ Internal Work:                                                       │ │ │
│ │ │  • Create attack fingerprints from enriched events                   │ │ │
│ │ │  • Compare fingerprints with historical attack patterns              │ │ │
│ │ │  • Detect repeated/known attacks                                     │ │ │
│ │ │                                                                      │ │ │
│ │ │ Example Fingerprint:                                                 │ │ │
│ │ │  failed_login + external_ip + high_frequency                         │ │ │
│ │ │                                                                      │ │ │
│ │ │ Decision Logic:                                                      │ │ │
│ │ │  • IF match found → known attack                                     │ │ │
│ │ │  • ELSE → new attack                                                 │ │ │
│ │ │                                                                      │ │ │
│ │ │ Tech Stack:                                                          │ │ │
│ │ │  • Python                                                            │ │ │
│ │ │  • PostgreSQL                                                        │ │ │
│ │ └─────────────────────┬───────────────────────────────┬────────────────┘ │ │
│ │                       │                               │                  │ │
│ │                       ▼                               ▼                  │ │
│ │        ┌────────────────────────┐      ┌──────────────────────────────┐ │ │
│ │        │ KNOWN ATTACK PATH      │      │ NEW ATTACK PATH             │ │ │
│ │        │------------------------│      │------------------------------│ │ │
│ │        │ Internal Work:         │      │ Internal Work:               │ │ │
│ │        │ • Fetch stored MITRE   │      │ • Send logs for deep ML      │ │ │
│ │        │ • Fetch stored score   │      │   processing                 │ │ │
│ │        │ • Fetch stored playbook│      │ • Perform anomaly detection  │ │ │
│ │        │ • Skip heavy analysis  │      │ • Perform UEBA analysis      │ │ │
│ │        └────────────┬───────────┘      └─────────────┬────────────────┘ │ │
│ │                     │                                ▼                  │ │
│ │                     │         ┌──────────────────────────────────────┐ │ │
│ │                     │         │ 7. RABBITMQ CONTAINER               │ │ │
│ │                     │         │--------------------------------------│ │ │
│ │                     │         │ Internal Work:                       │ │ │
│ │                     │         │ • Buffer incoming events             │ │ │
│ │                     │         │ • Prevent processing overload        │ │ │
│ │                     │         │ • Distribute events to workers       │ │ │
│ │                     │         │ • Enable asynchronous processing     │ │ │
│ │                     │         │                                      │ │ │
│ │                     │         │ Tech Stack:                          │ │ │
│ │                     │         │ • RabbitMQ                           │ │ │
│ │                     │         └────────────────┬─────────────────────┘ │ │
│ │                     │                          ▼                       │ │
│ │                     │         ┌──────────────────────────────────────┐ │ │
│ │                     │         │ 8. ML WORKER CONTAINERS             │ │ │
│ │                     │         │--------------------------------------│ │ │
│ │                     │         │ Internal Modules:                    │ │ │
│ │                     │         │                                      │ │ │
│ │                     │         │ (A) Preprocessing                    │ │ │
│ │                     │         │  • Clean/normalize logs              │ │ │
│ │                     │         │  • Remove invalid fields             │ │ │
│ │                     │         │                                      │ │ │
│ │                     │         │ (B) Feature Extraction               │ │ │
│ │                     │         │  • Convert logs → ML features        │ │ │
│ │                     │         │  • Generate time-series patterns     │ │ │
│ │                     │         │                                      │ │ │
│ │                     │         │ (C) Detection Engine                 │ │ │
│ │                     │         │  • Detect anomalies                  │ │ │
│ │                     │         │  • Generate anomaly scores           │ │ │
│ │                     │         │                                      │ │ │
│ │                     │         │ (D) UEBA                             │ │ │
│ │                     │         │  • Compare user behavior baseline    │ │ │
│ │                     │         │  • Detect abnormal activity          │ │ │
│ │                     │         │                                      │ │ │
│ │                     │         │ Tech Stack:                          │ │ │
│ │                     │         │ • pandas                             │ │ │
│ │                     │         │ • tsfresh                            │ │ │
│ │                     │         │ • PyOD                               │ │ │
│ │                     │         │ • Python                             │ │ │
│ │                     │         └────────────────┬─────────────────────┘ │ │
│ │                     │                          ▼                       │ │
│ │                     │         ┌──────────────────────────────────────┐ │ │
│ │                     │         │ 9. CORRELATION ENGINE               │ │ │
│ │                     │         │--------------------------------------│ │ │
│ │                     │         │ Internal Work:                       │ │ │
│ │                     │         │ • Build attack graphs                │ │ │
│ │                     │         │ • Link events across systems         │ │ │
│ │                     │         │ • Detect multi-stage attacks         │ │ │
│ │                     │         │ • Build attack chains                │ │ │
│ │                     │         │                                      │ │ │
│ │                     │         │ Graph Example:                       │ │ │
│ │                     │         │ User → IP → Event → Host             │ │ │
│ │                     │         │                                      │ │ │
│ │                     │         │ Tech Stack:                          │ │ │
│ │                     │         │ • NetworkX                           │ │ │
│ │                     │         └────────────────┬─────────────────────┘ │ │
│ │                     │                          ▼                       │ │
│ │                     │         ┌──────────────────────────────────────┐ │ │
│ │                     │         │ 10. MITRE ATT&CK MAPPING            │ │ │
│ │                     │         │--------------------------------------│ │ │
│ │                     │         │ Internal Work:                       │ │ │
│ │                     │         │ • Map attacks → MITRE techniques     │ │ │
│ │                     │         │ • Identify attack tactics            │ │ │
│ │                     │         │ • Add threat intelligence context    │ │ │
│ │                     │         │                                      │ │ │
│ │                     │         │ Example:                             │ │ │
│ │                     │         │ Failed Login → T1110 Brute Force     │ │ │
│ │                     │         │                                      │ │ │
│ │                     │         │ Tech Stack:                          │ │ │
│ │                     │         │ • MITRE ATT&CK Framework             │ │ │
│ │                     │         └────────────────┬─────────────────────┘ │ │
│ │                     │                          ▼                       │ │
│ │                     │         ┌──────────────────────────────────────┐ │ │
│ │                     │         │ 11.         │ │ │
│ │                     │         │--------------------------------------│ │ │
│ │                     │         │ Internal Work:                       │ │ │
│ │                     │         │ • Combine anomaly score              │ │ │
│ │                     │         │ • Combine UEBA confidence            │ │ │
│ │                     │         │ • Combine graph correlation strength │ │ │
│ │                     │         │ • Combine MITRE confidence           │ │ │
│ │                     │         │                                      │ │ │
│ │                     │         │ Final Output:                        │ │ │
│ │                     │         │ • LOW / MEDIUM / HIGH risk           │ │ │
│ │                     │         └────────────────┬─────────────────────┘ │ │
│ │                     └──────────────────────────┴───────────────────────┘ │ │
│ │                                                                          │ │
│ │                                ▼                                         │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ 12. POSTGRESQL CONTAINER                                             │ │ │
│ │ │----------------------------------------------------------------------│ │ │
│ │ │ Purpose: Persistent incident knowledge base                          │ │ │
│ │ │                                                                      │ │ │
│ │ │ Stores:                                                              │ │ │
│ │ │  • Incident history                                                  │ │ │
│ │ │  • Fingerprints                                                      │ │ │
│ │ │  • MITRE mappings                                                    │ │ │
│ │ │  • Risk scores                                                       │ │ │
│ │ │  • Generated playbooks                                               │ │ │
│ │ │                                                                      │ │ │
│ │ │ Tech Stack:                                                          │ │ │
│ │ │  • PostgreSQL                                                        │ │ │
│ │ └──────────────────────────────┬───────────────────────────────────────┘ │ │
│ │                                ▼                                         │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ 13. PLAYBOOK GENERATION ENGINE                                       │ │ │
│ │ │----------------------------------------------------------------------│ │ │
│ │ │ Internal Work:                                                       │ │ │
│ │ │  • Generate rule-based responses                                     │ │ │
│ │ │  • Use MITRE-guided remediation                                      │ │ │
│ │ │  • Build step-by-step analyst actions                                │ │ │
│ │ │                                                                      │ │ │
│ │ │ Example Playbook:                                                    │ │ │
│ │ │  1. Block attacker IP                                                │ │ │
│ │ │  2. Lock affected account                                            │ │ │
│ │ │  3. Enable MFA                                                       │ │ │
│ │ │                                                                      │ │ │
│ │ │ Tech Stack:                                                          │ │ │
│ │ │  • Python                                                            │ │ │
│ │ └──────────────────────────────┬───────────────────────────────────────┘ │ │
│ │                                ▼                                         │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ 14. OLLAMA LLM CONTAINER                                             │ │ │
│ │ │----------------------------------------------------------------------│ │ │
│ │ │ Internal Work:                                                       │ │ │
│ │ │  • Enhance playbooks using local LLM                                 │ │ │
│ │ │  • Explain incidents in human-readable form                          │ │ │
│ │ │  • Generate remediation guidance                                     │ │ │
│ │ │                                                                      │ │ │
│ │ │ Security Requirement:                                                │ │ │
│ │ │  • Fully offline inference                                           │ │ │
│ │ │                                                                      │ │ │
│ │ │ Tech Stack:                                                          │ │ │
│ │ │  • Ollama                                                            │ │ │
│ │ │  • Local LLM Models                                                  │ │ │
│ │ └──────────────────────────────┬───────────────────────────────────────┘ │ │
│ │                                ▼                                         │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ 15. FASTAPI CONTAINER                                                │ │ │
│ │ │----------------------------------------------------------------------│ │ │
│ │ │ Internal Work:                                                       │ │ │
│ │ │  • Provide REST API endpoints                                        │ │ │
│ │ │  • Serve alerts/incidents/playbooks                                  │ │ │
│ │ │  • Connect frontend dashboard                                        │ │ │
│ │ │                                                                      │ │ │
│ │ │ API Endpoints:                                                       │ │ │
│ │ │  • /alerts                                                           │ │ │
│ │ │  • /incidents                                                        │ │ │
│ │ │  • /analysis                                                         │ │ │
│ │ │  • /playbook                                                         │ │ │
│ │ │                                                                      │ │ │
│ │ │ Tech Stack:                                                          │ │ │
│ │ │  • FastAPI                                                           │ │ │
│ │ └──────────────────────────────┬───────────────────────────────────────┘ │ │
│ │                                ▼                                         │ │
│ │ ┌──────────────────────────────────────────────────────────────────────┐ │ │
│ │ │ 16. DASHBOARD FRONTEND                                               │ │ │
│ │ │----------------------------------------------------------------------│ │ │
│ │ │ Internal Work:                                                       │ │ │
│ │ │  • Display alerts and incidents                                      │ │ │
│ │ │  • Visualize attack chains                                           │ │ │
│ │ │  • Show MITRE mappings                                               │ │ │
│ │ │  • Display generated playbooks                                       │ │ │
│ │ │  • Display risk scoring dashboards                                   │ │ │
│ │ │                                                                      │ │ │
│ │ │ Tech Stack:                                                          │ │ │
│ │ │  • React                                                             │ │ │
│ │ │  • Chart.js                                                          │ │ │
│ │ └──────────────────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

# 🔥 FINAL PIPELINE SUMMARY

```text
Synthetic Logs / Dummy Apps
        ↓
Wazuh Collection
        ↓
OpenSearch Storage
        ↓
Python Ingestion
        ↓
Log Enrichment
        ↓
Signature/Fingerprint Check
        ↓
Known Attack → Fast Response
        ↓
New Attack → RabbitMQ
        ↓
ML + UEBA Processing
        ↓
Correlation Engine
        ↓
MITRE ATT&CK Mapping
        ↓
Fidelity Ranking
        ↓
PostgreSQL Storage
        ↓
Playbook Generation
        ↓
Ollama LLM Enhancement
        ↓
FastAPI
        ↓
Dashboard
```

---

# 🧠 FINAL PROJECT IDENTITY

> A fully offline Dockerized autonomous cyber incident response platform that performs AI-driven anomaly detection, UEBA analytics, attack correlation, MITRE ATT&CK mapping, fidelity scoring, signature-based attack memory, and automated playbook generation.