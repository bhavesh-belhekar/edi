# Wazuh Telemetry Ingestion & Streaming Phase

The Synthetic Telemetry Engine now behaves like a live enterprise deployment. Instead of relying on static datasets, this phase introduces a simulated real-time ingestion pipeline monitored directly by an embedded Wazuh SIEM stack.

### 🏗 Architecture Diagram

```text
  [generate_logs.py] (creates dataset chunk)
           ↓
  synthetic_logs/output/*.ndjson
           ↓
  [stream_logs.py] (replays JSON line-by-line simulating real time delays)
           ↓
  wazuh_logs/*.log (auth.log, endpoint.log, etc)
           ↓
  [Wazuh Manager (ossec)] (ingests JSON, decodes, evaluates rules)
           ↓
  [Wazuh Indexer] (stores indexed alerts and context)
           ↓
  [Wazuh Dashboard] (UI for SOC Analysts)
```

### ⚡ Volume Mapping Strategy
- Directory: `./wazuh_logs/`
- Bound to **`synthetic-logs`** as `/app/wazuh_logs`
- Bound to **`wazuh.manager`** as `/var/ossec/logs/synthetic_telemetry:ro`

Because this directory is a shared mount, the Python stream writing append operations (`>>`) inside the logger container are immediately recognized by `ossec-logcollector` inside the adjoining Wazuh container!

---

## 🚀 Execution Workflow

Here is how to get the entire simulated SIEM stack humming:

### 1. Configure Memory
Wazuh requires `vm.max_map_count` configuration on Linux hosts. Run this on your host if Wazuh Indexer fails:
```bash
sudo sysctl -w vm.max_map_count=262144
```

### 2. Generate a Fresh Telemetry Backlog
Before you can stream telemetry, you need a dataset to replay.
```bash
docker compose run --rm synthetic-logs python synthetic_logs/generate_logs.py --count 1000 --attacks 5
```

### 3. Spin Up the Stack
Bring up the Wazuh ecosystem and the streaming container in detached mode.
```bash
docker compose up -d
```

### 4. Monitor the Telemetry Stream
Tail the logs to watch the `synthetic-logs` container systematically feed events into the shared volume based on exact chronometric timings:
```bash
docker compose logs -f synthetic-logs
```

### 5. Access the Wazuh Dashboard
Wait a few minutes for the Indexer and Manager cluster to initialize, then navigate to:
**URL:** `https://localhost:443`
*(Username: `admin`, Password: `admin`)*

You will see custom rules (like Rule `100001` or `100003` for C2 Firewalls) triggered immediately in the UI as the log streaming container continues injecting correlated data!

---

### Custom Alert Schemas
We implemented standalone detection decoders for Wazuh inside `wazuh_config/decoders/synthetic_decoders.xml` to parse our custom `{"event_id":...}` format dynamically mapped with MITRE definitions inside `wazuh_config/rules/synthetic_rules.xml`.
