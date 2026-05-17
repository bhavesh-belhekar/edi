# Wazuh Detection Engineering

This document outlines the custom SOC-grade detection engineering implementation within the Wazuh ecosystem for synthetic telemetry.

## Overview
The platform generates synthetic JSON logs representing Endpoint, Auth, DNS, and Network activities. These logs are ingested via Filebeat/local-file and decoded using Wazuh's native `JSON_Decoder`. 

To upgrade from simple log ingestion to a professional detection platform, we implemented a custom ruleset (`synthetic_rules.xml`) mapped directly to the MITRE ATT&CK framework and leveraging native Wazuh correlation capabilities.

## Rule Hierarchy

All rules belong to the `synthetic_telemetry` group. 

- **Base Rule (`110000`):** Matches all incoming synthetic NDJSON telemetry.
- **Authentication Detections (`1101xx`):**
  - `110101`: Successful login (T1078)
  - `110102`: Failed login (T1110)
  - `110103`: Suspicious login outside business hours
  - `110104`: Interactive login by a service account (T1078.002)
- **Endpoint Detections (`1102xx`):**
  - `110201`: Process execution
  - `110202`: Suspicious PowerShell execution (e.g., EncodedCommand) (T1059.001)
  - `110203`: Credential dumping/lateral movement tools (mimikatz.exe, psexec.exe) (T1003)
  - `110204`: Persistence behavior (schtasks, reg) (T1053, T1112)
- **DNS Detections (`1103xx`):**
  - `110301`: Standard DNS Query
  - `110302`: DGA / DNS Tunneling (high entropy) (T1071.004, T1568.002)
  - `110303`: Beaconing activity (T1071)
- **Network/Firewall Detections (`1104xx`):**
  - `110401`: Basic firewall/proxy activity
  - `110402`: Data Exfiltration via Proxy (> 1MB transfer) (T1041)
  - `110403`: Internal scanning / Lateral movement (Denied internal connections) (T1046)

## Correlation Engineering

Wazuh's native `<frequency>`, `<timeframe>`, and `<same_field>` tags were utilized to build composite alerts from discrete events.

### Brute Force (Rule `110601`)
- **Trigger:** 5 failed logins (`110102`) within 180 seconds.
- **Correlation Field:** `<same_field>user.username</same_field>`
- **Severity:** 11 (High)
- **MITRE:** T1110 (Brute Force)

### Multi-Stage Attack Chain (Rule `110602`)
- **Trigger:** 3 distinct events within 300 seconds that share the same Attack Chain ID.
- **Correlation Field:** `<same_field>correlation.attack_chain_id</same_field>`
- **Severity:** 14 (Critical)
- **Significance:** This bridges the gap between disparate logs (e.g., a proxy download followed by a mimikatz execution on an endpoint), uniting them under a single composite alert.

## Alert Severity Standards

Alert levels have been strictly tuned:
- **Level 3-4 (Informational):** Standard expected behavior (e.g., allowed firewall traffic, successful user login).
- **Level 5-7 (Low):** Minor anomalies (e.g., single failed login).
- **Level 8-9 (Medium):** Suspicious behavior requiring triage (e.g., beaconing, odd-hour logins).
- **Level 10-12 (High):** Clear malicious intent (e.g., Brute Force, Exfiltration, Mimikatz).
- **Level 13-14 (Critical):** Multi-stage coordinated attacks.

## Validation & Testing
1. Rules can be tested inside the Wazuh manager container using `/var/ossec/bin/wazuh-logtest`.
2. MITRE mappings natively populate the Wazuh Dashboard under **Threat Intelligence -> MITRE ATT&CK**.
3. All fields (including nested objects like `user.username`) are indexed and searchable in the **Discover** tab.
