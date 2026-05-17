# Cyber Incident Response System - Steps 1 to 3

This README documents the completed local development pipeline:

```text
Synthetic telemetry generator
  -> Wazuh Manager
  -> Wazuh Indexer / OpenSearch
  -> Wazuh Dashboard
```

The current setup is intended for local offline development on Windows + WSL2 Ubuntu + Docker Desktop.

Security is intentionally simplified for Step 3:

- OpenSearch/Wazuh Indexer runs over HTTP.
- OpenSearch security is disabled.
- Dashboard SSL is disabled.
- Certificates are not required.

Do not use this exact security posture in production.

## Step 1 - Synthetic Telemetry Generation

Step 1 generates continuous synthetic security telemetry and writes it into host log files.

Generated log files:

```text
wazuh_logs/auth.log
wazuh_logs/dns.log
wazuh_logs/endpoint.log
wazuh_logs/firewall.log
wazuh_logs/proxy.log
```

Container:

```text
soc_telemetry_generator
```

Purpose:

- Simulates authentication, DNS, endpoint, firewall, and proxy telemetry.
- Continuously appends JSON events to local log files.
- Provides realistic test input for Wazuh.

Run:

```bash
cd /mnt/d/edi
docker build -t edi_synthetic-logs:latest .
docker rm -f soc_telemetry_generator 2>/dev/null || true

docker run -d \
  --name soc_telemetry_generator \
  --network edi_default \
  --restart unless-stopped \
  -e PYTHONPATH=/app \
  -e PYTHONUNBUFFERED=1 \
  -v /mnt/d/edi:/app \
  -v /mnt/d/edi/synthetic_logs/output:/app/synthetic_logs/output \
  -v /mnt/d/edi/wazuh_logs:/app/wazuh_logs \
  edi_synthetic-logs:latest \
  python synthetic_logs/stream_logs.py --continuous --speed 2.0
```

Validate:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
tail -n 3 /mnt/d/edi/wazuh_logs/auth.log
tail -n 3 /mnt/d/edi/wazuh_logs/firewall.log
```

Expected:

- `soc_telemetry_generator` is running.
- Log files contain newline-delimited JSON events.

## Step 2 - Wazuh Manager Parsing and Alerting

Step 2 configures Wazuh Manager to monitor the synthetic telemetry files, parse JSON logs, apply custom rules, and generate Wazuh alerts.

Container:

```text
wazuh.manager
```

Important mounted path:

```text
/mnt/d/edi/wazuh_logs
  -> /var/ossec/logs/synthetic_telemetry:ro
```

Custom files:

```text
wazuh_config/setup_wazuh.sh
wazuh_config/decoders/synthetic_decoders.xml
wazuh_config/rules/synthetic_rules.xml
```

Purpose:

- Installs custom decoder and rule files.
- Adds exactly one synthetic `<localfile>` monitor block.
- Avoids duplicate synthetic log monitoring.
- Creates required Wazuh runtime log directories.
- Keeps `wazuh-analysisd` and `wazuh-logcollector` stable.

Run:

```bash
docker rm -f wazuh.manager 2>/dev/null || true

docker run -d \
  --name wazuh.manager \
  --hostname wazuh.manager \
  --network edi_default \
  --restart unless-stopped \
  -p 1514:1514 \
  -p 1515:1515 \
  -p 514:514/udp \
  -p 55000:55000 \
  -e INDEXER_URL=http://wazuh.indexer:9200 \
  -e INDEXER_USERNAME=admin \
  -e INDEXER_PASSWORD=admin \
  -v edi_wazuh_manager_etc:/var/ossec/etc \
  -v edi_wazuh_manager_logs:/var/ossec/logs \
  -v edi_wazuh_manager_queue:/var/ossec/queue \
  -v edi_wazuh_manager_var_multigroups:/var/ossec/var/multigroups \
  -v edi_wazuh_manager_integrations:/var/ossec/integrations \
  -v edi_wazuh_manager_active_response:/var/ossec/active-response/bin \
  -v edi_wazuh_manager_agentless:/var/ossec/agentless \
  -v edi_wazuh_manager_wodles:/var/ossec/wodles \
  -v edi_wazuh_filebeat_etc:/etc/filebeat \
  -v edi_wazuh_filebeat_var:/var/lib/filebeat \
  -v /mnt/d/edi/wazuh_logs:/var/ossec/logs/synthetic_telemetry:ro \
  -v /mnt/d/edi/wazuh_config/decoders/synthetic_decoders.xml:/tmp/synthetic_decoders.xml:ro \
  -v /mnt/d/edi/wazuh_config/rules/synthetic_rules.xml:/tmp/synthetic_rules.xml:ro \
  -v /mnt/d/edi/wazuh_config/setup_wazuh.sh:/setup_wazuh.sh:ro \
  --entrypoint /bin/bash \
  wazuh/wazuh-manager:4.9.0 \
  /setup_wazuh.sh
```

Validate services:

```bash
docker exec -it wazuh.manager /var/ossec/bin/wazuh-control status
```

Required:

```text
wazuh-analysisd is running...
wazuh-logcollector is running...
```

Validate synthetic monitor count:

```bash
docker exec -it wazuh.manager grep -c "/var/ossec/logs/synthetic_telemetry" /var/ossec/etc/ossec.conf
```

Expected:

```text
1
```

Validate rules with logtest:

```bash
docker exec -it wazuh.manager /var/ossec/bin/wazuh-logtest
```

Paste:

```json
{"event_id":"step2-test-001","timestamp":"2026-05-16T23:59:00+00:00","event_type":"failed_login","severity":"high","source":{"ip":"10.0.0.5"},"user":{"username":"step2_user"},"raw_log":"Step 2 synthetic test"}
```

Expected:

```text
id: '110002'
description: 'Synthetic high severity event: failed_login'
**Alert to be generated.
```

## Step 3 - OpenSearch / Wazuh Indexer Integration

Step 3 stores Wazuh alerts in OpenSearch-compatible Wazuh Indexer and exposes them through Wazuh Dashboard.

Containers:

```text
wazuh.indexer
wazuh.dashboard
```

Ports:

```text
9200  -> Wazuh Indexer / OpenSearch API
5601  -> Wazuh Dashboard
55000 -> Wazuh Manager API
```

Purpose:

- Stores Wazuh alerts in `wazuh-alerts-*` indices.
- Enables centralized searching and querying.
- Provides dashboard UI at `http://localhost:5601`.

Local indexer config:

```text
wazuh_config/indexer/opensearch.yml
```

Local dashboard config:

```text
wazuh_config/dashboard/opensearch_dashboards.yml
wazuh_config/dashboard/wazuh.yml
```

Set WSL2 kernel requirement:

```bash
sudo sysctl -w vm.max_map_count=262144
```

Run Wazuh Indexer:

```bash
docker rm -f wazuh.indexer 2>/dev/null || true

docker run -d \
  --name wazuh.indexer \
  --hostname wazuh.indexer \
  --network edi_default \
  --restart unless-stopped \
  -p 9200:9200 \
  -e OPENSEARCH_JAVA_OPTS="-Xms1g -Xmx1g" \
  -e DISABLE_SECURITY_PLUGIN=true \
  -e DISABLE_INSTALL_DEMO_CONFIG=true \
  -e DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true \
  --ulimit memlock=-1:-1 \
  --ulimit nofile=65536:65536 \
  -v edi_wazuh_indexer_data:/var/lib/wazuh-indexer \
  -v /mnt/d/edi/wazuh_config/indexer/opensearch.yml:/usr/share/wazuh-indexer/opensearch.yml:ro \
  wazuh/wazuh-indexer:4.9.0
```

Run Wazuh Dashboard:

```bash
docker rm -f wazuh.dashboard 2>/dev/null || true

docker run -d \
  --name wazuh.dashboard \
  --hostname wazuh.dashboard \
  --network edi_default \
  --restart unless-stopped \
  -p 5601:5601 \
  -e INDEXER_URL=http://wazuh.indexer:9200 \
  -e INDEXER_USERNAME=admin \
  -e INDEXER_PASSWORD=admin \
  -e OPENSEARCH_HOSTS='["http://wazuh.indexer:9200"]' \
  -e WAZUH_API_URL=https://wazuh.manager \
  -e API_USERNAME=wazuh-wui \
  -e API_PASSWORD=wazuh-wui \
  -v /mnt/d/edi/wazuh_config/dashboard/opensearch_dashboards.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml:ro \
  -v /mnt/d/edi/wazuh_config/dashboard/wazuh.yml:/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml:ro \
  wazuh/wazuh-dashboard:4.9.0
```

Validate indexer:

```bash
curl http://localhost:9200
curl http://localhost:9200/_cluster/health?pretty
curl -s "http://localhost:9200/_cat/indices?v"
```

Expected:

```text
cluster status: green
wazuh-alerts-4.x-YYYY.MM.DD exists
```

Validate manager to indexer:

```bash
docker exec -it wazuh.manager filebeat test output
```

Expected:

```text
dial up... OK
talk to server... OK
TLS... WARN secure connection disabled
```

The TLS warning is expected because local Step 3 uses HTTP/no-security mode.

Validate indexed alerts:

```bash
curl -s "http://localhost:9200/_cat/indices/wazuh-alerts-*?v"
curl -s "http://localhost:9200/wazuh-alerts-*/_search?size=3&pretty" \
  -H "Content-Type: application/json" \
  -d '{"query":{"match_all":{}}}'
```

Validate dashboard:

```bash
curl -I http://localhost:5601
```

Expected:

```text
HTTP/1.1 302 Found
```

Open:

```text
http://localhost:5601/app/wz-home
```

Expected:

- Wazuh Dashboard loads.
- Overview page is visible.
- Alerts are backed by the `wazuh-alerts-*` index in Wazuh Indexer.

## Why Local Security Is Disabled

The default Wazuh secure Docker deployment expects:

- OpenSearch security plugin enabled.
- TLS certificates mounted into indexer and dashboard containers.
- HTTPS between manager, indexer, and dashboard.
- Correct certificate ownership and permissions.

For this local offline development environment, partial certificate configuration caused:

```text
failed to load plugin class [org.opensearch.security.OpenSearchSecurityPlugin]
access denied "/etc/wazuh-indexer/certs/indexer.pem"
```

So Step 3 uses HTTP/no-security mode to stabilize indexing and querying first.

Production implications:

- Do not expose this setup outside localhost/private lab use.
- Re-enable OpenSearch security before production.
- Generate and mount certificates.
- Switch URLs back to HTTPS.
- Use real secrets instead of defaults.

## Step 4 - Python Ingestion Service

Step 4 adds an offline Python ingestion container that reads only new logs from OpenSearch, normalizes them, removes duplicates, and writes clean NDJSON for downstream enrichment.

Service: `ingestion.service`

Key behavior:

- Boots from the latest existing OpenSearch timestamp to avoid reprocessing history
- Fetches only documents where `@timestamp > last_fetched_timestamp`
- Uses `search_after` pagination with `@timestamp` and `_id`
- Deduplicates by `event_id` and OpenSearch `_id`
- Normalizes Wazuh alert fields into the shared `SecurityEvent` schema
- Persists output to `ingestion_service/output/normalized_events_<YYYYMMDD>.ndjson`
- Maintains state in `ingestion_service/state/last_fetch_state.json`

Startup:

```bash
cd /mnt/d/edi
docker-compose up -d ingestion.service
```

Verify the ingestion service:

```bash
docker-compose ps ingestion.service
docker-compose logs --tail 20 ingestion.service
ls -1 ingestion_service/output
tail -n 5 ingestion_service/output/normalized_events_$(date +%Y%m%d).ndjson
```

## Docker Compose v1 Warning

This environment uses legacy `docker-compose` v1.29.2, which can crash with:

```text
KeyError: 'ContainerConfig'
```

This is a Compose v1 compatibility issue with newer Docker Desktop image metadata.

Workaround:

- Remove stale containers manually with `docker rm -f`.
- Use direct `docker run` commands from this README.
- Later install Docker Compose v2 and use `docker compose`.

## Final Completion Criteria

Steps 1 to 3 are complete when all of these pass:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
docker exec -it wazuh.manager /var/ossec/bin/wazuh-control status
docker exec -it wazuh.manager filebeat test output
curl http://localhost:9200/_cluster/health?pretty
curl -s "http://localhost:9200/_cat/indices/wazuh-alerts-*?v"
curl -I http://localhost:5601
```

Expected final state:

- `soc_telemetry_generator` running.
- `wazuh.manager` healthy.
- `wazuh.indexer` running.
- `wazuh.dashboard` running.
- `wazuh-analysisd` running.
- `wazuh-logcollector` running.
- OpenSearch cluster health is green.
- `wazuh-alerts-*` index exists and contains documents.
- Wazuh Dashboard opens at `http://localhost:5601/app/wz-home`.
