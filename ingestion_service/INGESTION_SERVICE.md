# Ingestion Service

This service polls OpenSearch for new Wazuh alert documents, filters on `rule.groups = synthetic_telemetry`, normalizes the events into the unified schema, and writes them to local NDJSON output.

## What it does

- Connects to OpenSearch
- Fetches only new synthetic telemetry events
- Normalizes each hit into the common event model
- Stores progress in a checkpoint file so restarts are safe
- Appends normalized events to `logs/normalized_events.ndjson`

## Main files

- `main.py` - service entrypoint and polling loop
- `config.py` - environment-based settings
- `opensearch_client.py` - OpenSearch connection wrapper
- `fetcher.py` - incremental event fetching
- `normalizer.py` - event normalization logic
- `checkpoint.py` - restart-safe checkpoint storage
- `writer.py` - NDJSON output writer
- `models.py` - local ingestion models

## Configuration

Environment variables used by the service:

- `OPENSEARCH_HOST`
- `OPENSEARCH_PORT`
- `OPENSEARCH_USERNAME`
- `OPENSEARCH_PASSWORD`
- `OPENSEARCH_INDEX_PATTERN`
- `POLL_INTERVAL_SECONDS`
- `BATCH_SIZE`
- `REQUEST_TIMEOUT_SECONDS`
- `CHECKPOINT_PATH`
- `OUTPUT_PATH`

## Run locally

```bash
cd ingestion_service
python main.py
```

## Docker

The root `docker-compose.yml` starts this service as `ingestion.service` and mounts runtime output under `ingestion_service/logs/` and checkpoint state under `ingestion_service/state/`.
