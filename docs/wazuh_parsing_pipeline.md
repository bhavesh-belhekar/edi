# Wazuh Parsing Pipeline Debugging Documentation

## 1. How logs flow
The synthetic data generator outputs NDJSON logs directly into `synthetic_logs/output/`. These logs are mounted as a volume into the Wazuh manager container via Docker Compose.

## 2. Docker mount structure
- Generator path: `/app/synthetic_logs/output/`
- Wazuh Container path: `/var/ossec/logs/synthetic_telemetry`
Volume configuration in docker-compose.yml maps the host folder so Wazuh agent can read from there.

## 3. Agent to manager pipeline
The local Wazuh instance configuration monitors `/var/ossec/logs/synthetic_telemetry/*.ndjson` using `<localfile>` blocks with `<log_format>json</log_format>`. Each JSON string is sent directly to the agent-manager parsing pipeline.

## 4. Decoder hierarchy
A custom XML decoder `synthetic_decoders.xml` relies on basic pattern matching (`<prematch>"event_type"</prematch>`) combined with the `JSON_Decoder` plugin as a child. This automatically extracts all fields dynamically.
- `synthetic-json-base`: Parent matching `event_type`
- `synthetic-json-child`: Calls `JSON_Decoder` plugin for field extraction.

## 5. Rule hierarchy
Rules are layered based on the parent ID `100000`. We leverage simple field matches, dynamically capturing fields like `event_type`, `process.command_line`, and `detection.risk_score` to build high-severity alerts directly from the extracted JSON data. MITRE ATT&CK IDs are included using `<mitre><id>` blocks.

## 6. Parsing workflow
1. Event read from NDJSON.
2. Matched against `synthetic-json-base` decoder.
3. Passed to `JSON_Decoder` for field extraction.
4. Matched against generic rule `100000`.
5. Evaluated against child rules (e.g. `100001` - `100007`) for specific threats.

## 7. Troubleshooting steps
- Confirm log format with `cat logfile.ndjson | jq .`.
- Check `/var/ossec/logs/ossec.log` for ingestion errors.
- Test decoding manually with `docker exec -it wazuh.manager /var/ossec/bin/wazuh-logtest`.
- Check archives in `/var/ossec/logs/archives/archives.json`.

## 8. Example parsed alert
```json
{
  "timestamp": "2026-05-17T00:00:00.000+0000",
  "rule": {
    "level": 12,
    "description": "Suspicious PowerShell Execution Detected",
    "id": "100001",
    "mitre": {
      "id": ["T1059.001"],
      "tactic": ["Execution"],
      "technique": ["Command and Scripting Interpreter: PowerShell"]
    }
  },
  "decoder": {
    "name": "synthetic-json-base"
  },
  "data": {
    "event_type": "suspicious_powershell",
    "process": {
      "command_line": "powershell.exe -e"
    }
  }
}
```
