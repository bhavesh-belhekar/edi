"""Entrypoint for the Python ingestion service container."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, List

from checkpoint import CheckpointStore
from config import IngestionSettings, settings
from enricher import enrich_event
from fetcher import IncrementalFetcher
from models import NormalizedEvent
from normalizer import EventNormalizer
from opensearch_client import OpenSearchClient
from split_writer import SplitEventWriter
from writer import NDJSONWriter
from pydantic import ValidationError

# -- Import SOC Pipeline components --
from shared.schemas import SecurityEvent
from src.services.signature_engine.matcher import match_event
from src.services.signature_engine.database import FingerprintDB
from src.services.signature_engine.rabbitmq_publisher import RabbitMQPublisher


LOGGER = logging.getLogger("ingestion_service")


def configure_logging() -> None:
    """Configure concise structured logging for container output."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def wait_for_opensearch(client: OpenSearchClient, runtime_settings: IngestionSettings) -> None:
    """Retry until OpenSearch responds or the retry budget is exhausted."""

    for attempt in range(1, runtime_settings.max_retries + 1):
        try:
            if client.ping():
                LOGGER.info(
                    "event=opensearch_connection_success host=%s port=%s attempt=%s",
                    runtime_settings.opensearch_host,
                    runtime_settings.opensearch_port,
                    attempt,
                )
                return
        except Exception as error:
            LOGGER.warning(
                "event=opensearch_connection_retry attempt=%s error=%s",
                attempt,
                error,
            )

        time.sleep(runtime_settings.retry_backoff_seconds)

    raise RuntimeError("OpenSearch did not become ready in time")


def bootstrap_checkpoint_if_needed(
    fetcher: IncrementalFetcher,
    checkpoint_store: CheckpointStore,
    runtime_settings: IngestionSettings,
) -> None:
    """Start from the newest existing synthetic alert when no checkpoint exists."""

    if checkpoint_store.state.last_timestamp is not None:
        LOGGER.info(
            "event=checkpoint_recovered last_timestamp=%s processed_ids=%s",
            checkpoint_store.state.last_timestamp,
            len(checkpoint_store.state.processed_ids),
        )
        return

    latest_hit = fetcher.latest_matching_hit()
    if latest_hit is None:
        LOGGER.info("event=checkpoint_bootstrap empty_index=true")
        checkpoint_store.save()
        return

    latest_source = latest_hit.get("_source", {}) if isinstance(latest_hit.get("_source", {}), dict) else {}
    latest_timestamp = latest_source.get("@timestamp") or latest_source.get("timestamp")
    checkpoint_store.state.last_timestamp = (
        str(latest_timestamp) if latest_timestamp else datetime.now(timezone.utc).isoformat()
    )
    checkpoint_store.state.last_sort = None
    checkpoint_store.save()
    LOGGER.info(
        "event=checkpoint_bootstrap last_timestamp=%s index_pattern=%s",
        checkpoint_store.state.last_timestamp,
        runtime_settings.opensearch_index_pattern,
    )


def validate_schema(normalizer: EventNormalizer, sample_hit: dict) -> NormalizedEvent:
    """Validate a sample hit against the normalized schema."""

    normalized_event = normalizer.normalize(sample_hit)
    return NormalizedEvent.model_validate(normalized_event.model_dump(mode="json", exclude_none=False))


def process_one_cycle(
    fetcher: IncrementalFetcher,
    normalizer: EventNormalizer,
    checkpoint_store: CheckpointStore,
    writer: NDJSONWriter,
    split_writer: SplitEventWriter,
    fingerprint_db: FingerprintDB,
    rabbitmq_publisher: RabbitMQPublisher,
) -> tuple[int, int]:
    """Fetch, normalize, enrich, deduplicate, persist, and checkpoint one polling cycle."""

    fetched_count = 0
    normalized_count = 0

    for batch in fetcher.iter_batches(checkpoint_store):
        fetched_count += len(batch)
        normalized_events: List[NormalizedEvent] = []
        pending_updates: List[tuple[NormalizedEvent, Any]] = []
        batch_seen_ids: set[str] = set()

        for hit in batch:
            event_id = normalizer.extract_event_id(hit)
            if checkpoint_store.is_duplicate(event_id) or event_id in batch_seen_ids:
                continue

            # Normalize the event (now extracts nested JSON from raw_log)
            normalized_event = normalizer.normalize(hit)
            event_valid = True
            
            # Apply in-process enrichment
            try:
                normalized_event = enrich_event(normalized_event)
                LOGGER.debug("event_id=%s enriched type=%s risk_level=%s", 
                           normalized_event.event_id, 
                           normalized_event.event_type,
                           normalized_event.detection.risk_level if normalized_event.detection else None)
                
                # --- STEP 1 & 2 & 3: Pass to Signature/Fingerprint Engine ---
                # Convert NormalizedEvent to SecurityEvent for the pipeline
                sec_event = SecurityEvent.model_validate(normalized_event.model_dump(mode="json", exclude_none=True))
                
                match_result = match_event(
                    event=sec_event,
                    db=fingerprint_db,
                    publisher=rabbitmq_publisher
                )
                
                # Update our normalized_event with the result (if modifications were made)
                normalized_event = NormalizedEvent.model_validate(match_result.event.model_dump(mode="json"))

            except ValidationError as ve:
                failed_fields = [e["loc"][0] if e["loc"] else "unknown" for e in ve.errors()]
                LOGGER.error(
                    "event_id=%s validation failed fields=%s error=%s - skipping event",
                    normalized_event.event_id,
                    failed_fields,
                    str(ve),
                )
                event_valid = False

            except Exception as e:
                LOGGER.warning(
                    "event_id=%s enrichment/signature failed (continuing): %s",
                    normalized_event.event_id,
                    e,
                )
            
            if event_valid:
                normalized_events.append(normalized_event)
                pending_updates.append((normalized_event, hit.get("sort")))
                batch_seen_ids.add(normalized_event.event_id)

        if normalized_events:
            # Write to main normalized output
            written = writer.append(normalized_events)
            
            # Write to split enriched outputs
            split_written = split_writer.write(normalized_events)
            
            normalized_count += written
            for normalized_event, sort_values in pending_updates:
                checkpoint_store.advance(
                    normalized_event.timestamp.isoformat(),
                    sort_values,
                    normalized_event.event_id,
                )
            checkpoint_store.save()
            LOGGER.info(
                "event=batch_written fetched=%s normalized=%s enriched=%s checkpoint_timestamp=%s",
                len(batch),
                written,
                split_written,
                checkpoint_store.state.last_timestamp,
            )

    return fetched_count, normalized_count


def run() -> None:
    """Run the continuous ingestion loop."""

    configure_logging()
    LOGGER.info("event=ingestion_service_start version=1.0 enrichment=enabled_internal")
    
    client = OpenSearchClient(settings)
    wait_for_opensearch(client, settings)

    checkpoint_store = CheckpointStore(settings.checkpoint_path)
    fetcher = IncrementalFetcher(client, settings)
    normalizer = EventNormalizer()
    writer = NDJSONWriter(settings.output_path)
    
    # Initialize split writer for enriched outputs
    # settings.output_path is a Path object like /app/logs/normalized_events.ndjson
    # We want to write enriched events to the logs directory with split files
    from pathlib import Path
    output_path_obj = Path(settings.output_path)
    processed_events_dir = str(output_path_obj.parent)  # Get /app/logs/ directory
    split_writer = SplitEventWriter(processed_events_dir)

    # Initialize Signature Engine connections
    fingerprint_db = FingerprintDB()
    rabbitmq_publisher = RabbitMQPublisher()

    bootstrap_checkpoint_if_needed(fetcher, checkpoint_store, settings)

    LOGGER.info(
        "event=ingestion_loop_started poll_interval=%s batch_size=%s normalized_path=%s processed_path=%s",
        settings.poll_interval_seconds,
        settings.batch_size,
        settings.output_path,
        processed_events_dir,
    )

    while True:
        try:
            fetched_count, normalized_count = process_one_cycle(
                fetcher, normalizer, checkpoint_store, writer, split_writer, fingerprint_db, rabbitmq_publisher
            )
            if fetched_count > 0:
                LOGGER.info(
                    "event=cycle_completed fetched=%s normalized=%s checkpoint_timestamp=%s",
                    fetched_count,
                    normalized_count,
                    checkpoint_store.state.last_timestamp,
                )
        except Exception as error:
            LOGGER.exception("event=ingestion_cycle_error error=%s", error)
            time.sleep(settings.retry_backoff_seconds)
            continue

        time.sleep(settings.poll_interval_seconds)


if __name__ == "__main__":
    run()
