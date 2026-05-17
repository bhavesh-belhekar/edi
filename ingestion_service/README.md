# Python OpenSearch Ingestion Service

This service continuously polls OpenSearch for new Wazuh alert documents, filters on `rule.groups = synthetic_telemetry`, normalizes the events into the unified schema, and appends them to a local NDJSON file.

## Runtime layout

- `main.py` orchestrates the service loop
- `config.py` loads environment settings
- `opensearch_client.py` handles the OpenSearch connection
- `fetcher.py` paginates only new telemetry events
- `normalizer.py` maps OpenSearch hits to the normalized event model
- `checkpoint.py` persists restart-safe progress in `checkpoint.json`
- `writer.py` appends normalized records to `logs/normalized_events.ndjson`

## Environment variables

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

## Local run

```bash
cd ingestion_service
python main.py
```

## Dockerized service

The root `docker-compose.yml` runs this service as `ingestion.service`, mounts `ingestion_service/checkpoint.json`, and persists normalized output under `ingestion_service/logs/`.
