# Python OpenSearch Ingestion Service

This service continuously polls OpenSearch for new Wazuh alert documents, normalizes them to a shared security event schema, prevents duplicate processing, and writes clean JSON to a local NDJSON file.

## Behavior

- Connects to OpenSearch at `http://wazuh.indexer:9200`
- Bootstraps against the latest existing document timestamp on first run
- Fetches only new documents with `@timestamp > last_fetched_timestamp`
- Normalizes data into the shared `SecurityEvent` contract
- Deduplicates by `event_id` and OpenSearch `_id`
- Persists clean JSON to `output/normalized_events_<YYYYMMDD>.ndjson`
- Stores ingestion state in `/app/state/last_fetch_state.json`

## Running locally

```bash
cd /mnt/d/edi/ingestion_service
python main.py
```

## Dockerized service

The root `docker-compose.yml` defines this service as `ingestion.service` and mounts the local code for development.
