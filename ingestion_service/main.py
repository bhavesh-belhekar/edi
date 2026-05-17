import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from dateutil import parser as date_parser
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opensearchpy import OpenSearch, RequestsHttpConnection  # type: ignore
    from opensearchpy.exceptions import ConnectionError as OpenSearchConnectionError, TransportError  # type: ignore
else:
    try:
        from opensearchpy import OpenSearch, RequestsHttpConnection
        from opensearchpy.exceptions import ConnectionError as OpenSearchConnectionError, TransportError
    except Exception:  # pragma: no cover - optional dependency in some environments
        OpenSearch = None  # type: ignore
        RequestsHttpConnection = None  # type: ignore
        OpenSearchConnectionError = Exception
        TransportError = Exception

from shared.schemas import (
    BehavioralFeatures,
    CorrelationInfo,
    DetectionInfo,
    DestinationInfo,
    DNSInfo,
    FirewallInfo,
    HTTPInfo,
    MITREAttackInfo,
    PlaybookInfo,
    ProcessInfo,
    ProxyInfo,
    SecurityEvent,
    SourceInfo,
    SystemInfo,
    UserInfo,
)

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ingestion_service")

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "wazuh.indexer")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")
OPENSEARCH_INDEX_PATTERN = os.getenv("OPENSEARCH_INDEX_PATTERN", "wazuh-alerts-4.x-*")
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "15"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "200"))
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/app/output")
STATE_FILE = os.getenv("STATE_FILE", "/app/state/last_fetch_state.json")
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "5"))
RETRY_BACKOFF_SECONDS = int(os.getenv("RETRY_BACKOFF_SECONDS", "5"))
MAX_PROCESSED_IDS = int(os.getenv("MAX_PROCESSED_IDS", "5000"))

DEFAULT_IP = "0.0.0.0"
DEFAULT_PORT = 0


def ensure_paths() -> None:
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)


def load_state() -> Dict[str, Any]:
    if not Path(STATE_FILE).exists():
        return {
            "last_fetch_timestamp": None,
            "last_sort": None,
            "processed_ids": [],
        }

    with open(STATE_FILE, "r", encoding="utf-8") as state_file:
        return json.load(state_file)


def save_state(state: Dict[str, Any]) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as state_file:
        json.dump(state, state_file, indent=2)


def parse_timestamp(raw_ts: Optional[str]) -> datetime:
    if not raw_ts:
        return datetime.now(timezone.utc)
    try:
        parsed = date_parser.parse(raw_ts)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def safe_str(value: Any, fallback: Optional[str] = None) -> str:
    if value is None:
        return fallback or ""
    return str(value)


def normalize_event(hit: Dict[str, Any]) -> Dict[str, Any]:
    source_doc = hit.get("_source", {})
    event_id = source_doc.get("event_id") or hit.get("_id") or str(uuid4())
    timestamp_value = source_doc.get("timestamp") or source_doc.get("@timestamp")
    timestamp = parse_timestamp(timestamp_value)

    source_block = source_doc.get("source", {}) or {}
    destination_block = source_doc.get("destination", {}) or {}
    user_block = source_doc.get("user", {}) or {}
    process_block = source_doc.get("process", {}) or {}
    system_block = source_doc.get("system", {}) or {}

    event_type_val = safe_str(
        source_doc.get("event_type") or source_doc.get("rule", {}).get("description") or "unknown_event"
    )
    raw_log_val = safe_str(
        source_doc.get("raw_log") or source_doc.get("full_log") or json.dumps(source_doc, default=str)
    )

    event = SecurityEvent(
        event_id=safe_str(event_id),
        timestamp=timestamp,
        event_type=event_type_val,
        severity=safe_str(source_doc.get("severity", "info")),
        source=SourceInfo(
            ip=safe_str(source_block.get("ip") or DEFAULT_IP, DEFAULT_IP),
            port=safe_int(source_block.get("port")) or DEFAULT_PORT,
            hostname=safe_str(source_block.get("hostname")),
            geo=safe_str(source_block.get("geo"), None),
        ),
        destination=DestinationInfo(
            ip=safe_str(destination_block.get("ip") or DEFAULT_IP, DEFAULT_IP),
            port=safe_int(destination_block.get("port")) or DEFAULT_PORT,
            hostname=safe_str(destination_block.get("hostname")),
        ),
        user=UserInfo(
            username=safe_str(user_block.get("username")),
            role=safe_str(user_block.get("role")),
            department=safe_str(user_block.get("department")),
        ),
        process=ProcessInfo(
            name=safe_str(process_block.get("name")),
            pid=safe_int(process_block.get("pid")),
            parent_process_name=safe_str(process_block.get("parent_process_name"), None),
            command_line=safe_str(process_block.get("command_line"), None),
        ),
        system=SystemInfo(
            os=safe_str(system_block.get("os")),
            container_id=safe_str(system_block.get("container_id"), None),
        ),
        http=HTTPInfo(
            method=safe_str(source_doc.get("http", {}).get("method"), None),
            endpoint=safe_str(source_doc.get("http", {}).get("endpoint"), None),
            status_code=safe_int(source_doc.get("http", {}).get("status_code")) or 0,
        ),
        dns=DNSInfo(
            queried_domain=safe_str(source_doc.get("dns", {}).get("queried_domain"), ""),
            query_type=safe_str(source_doc.get("dns", {}).get("query_type"), ""),
            resolved_ip=safe_str(source_doc.get("dns", {}).get("resolved_ip"), ""),
            response_code=safe_str(source_doc.get("dns", {}).get("response_code"), ""),
            ttl=safe_int(source_doc.get("dns", {}).get("ttl")),
        ),
        firewall=FirewallInfo(
            action=safe_str(source_doc.get("firewall", {}).get("action"), "unknown"),
            protocol=safe_str(source_doc.get("firewall", {}).get("protocol", "TCP")),
            bytes_sent=safe_int(source_doc.get("firewall", {}).get("bytes_sent")) or 0,
            bytes_received=safe_int(source_doc.get("firewall", {}).get("bytes_received")) or 0,
            session_duration_ms=safe_int(source_doc.get("firewall", {}).get("session_duration_ms")) or 0,
            rule_id=safe_str(source_doc.get("firewall", {}).get("rule_id"), None),
            direction=safe_str(source_doc.get("firewall", {}).get("direction", "outbound")),
        ),
        proxy=ProxyInfo(
            url=safe_str(source_doc.get("proxy", {}).get("url"), None),
            method=safe_str(source_doc.get("proxy", {}).get("method", "GET")),
            status_code=safe_int(source_doc.get("proxy", {}).get("status_code")) or 0,
            user_agent=safe_str(source_doc.get("proxy", {}).get("user_agent"), None),
            domain=safe_str(source_doc.get("proxy", {}).get("domain"), None),
            content_type=safe_str(source_doc.get("proxy", {}).get("content_type"), None),
            bytes_transferred=safe_int(source_doc.get("proxy", {}).get("bytes_transferred")) or 0,
            referrer=safe_str(source_doc.get("proxy", {}).get("referrer"), None),
            category=safe_str(source_doc.get("proxy", {}).get("category", "uncategorized")),
        ),
        behavioral_features=BehavioralFeatures(**(source_doc.get("behavioral_features") or {})),
        detection=DetectionInfo(**(source_doc.get("detection") or {})),
        correlation=CorrelationInfo(**(source_doc.get("correlation") or {})),
        mitre_attack=MITREAttackInfo(**(source_doc.get("mitre_attack") or {})),
        playbook=PlaybookInfo(**(source_doc.get("playbook") or {})),
        raw_log=raw_log_val,
    )

    event_payload = event.model_dump(exclude_none=True)
    event_payload["ingest_metadata"] = {
        "opensearch_index": hit.get("_index"),
        "opensearch_id": hit.get("_id"),
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }
    return event_payload


def build_client() -> Any:
    logger.info("Connecting to OpenSearch at %s:%s", OPENSEARCH_HOST, OPENSEARCH_PORT)
    if OpenSearch is None:
        raise RuntimeError("opensearchpy is not installed; cannot build OpenSearch client")

    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_compress=True,
        use_ssl=False,
        verify_certs=False,
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        connection_class=RequestsHttpConnection,
        timeout=30,
        max_retries=3,
        retry_on_timeout=True,
    )


def fetch_latest_index_timestamp(client: Any) -> str:
    response = client.search(
        index=OPENSEARCH_INDEX_PATTERN,
        body={
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "_source": ["@timestamp"],
        },
    )
    hits = response.get("hits", {}).get("hits", [])
    if not hits:
        return datetime.now(timezone.utc).isoformat()
    ts = hits[0].get("_source", {}).get("@timestamp")
    return ts or datetime.now(timezone.utc).isoformat()


def build_query(last_timestamp: Optional[str]) -> Dict[str, Any]:
    if last_timestamp is None:
        return {"match_all": {}}
    return {"range": {"@timestamp": {"gt": last_timestamp}}}


def fetch_new_documents(client: Any, state: Dict[str, Any]) -> List[Dict[str, Any]]:
    query = build_query(state.get("last_fetch_timestamp"))
    search_after = state.get("last_sort")
    sort_fields = [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}, {"_id": {"order": "asc"}}]
    docs: List[Dict[str, Any]] = []

    while True:
        body: Dict[str, Any] = {"size": BATCH_SIZE, "sort": sort_fields, "query": query}
        if search_after:
            body["search_after"] = search_after

        response = client.search(index=OPENSEARCH_INDEX_PATTERN, body=body)
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            break

        docs.extend(hits)
        if len(hits) < BATCH_SIZE:
            break

        search_after = hits[-1].get("sort")

    return docs


def write_events(events: List[Dict[str, Any]]) -> int:
    filename = Path(OUTPUT_DIR) / f"normalized_events_{datetime.now(timezone.utc).strftime('%Y%m%d')}.ndjson"
    with open(filename, "a", encoding="utf-8") as out_file:
        for event in events:
            out_file.write(json.dumps(event, default=str) + "\n")
    return len(events)


def append_processed_id(state: Dict[str, Any], event_id: str) -> None:
    processed_ids = state.setdefault("processed_ids", [])
    processed_ids.append(event_id)
    if len(processed_ids) > MAX_PROCESSED_IDS:
        state["processed_ids"] = processed_ids[-MAX_PROCESSED_IDS:]


def bootstrap_initial_state(client: Any, state: Dict[str, Any]) -> Dict[str, Any]:
    last_timestamp = fetch_latest_index_timestamp(client)
    state["last_fetch_timestamp"] = last_timestamp
    state["last_sort"] = None
    state["processed_ids"] = []
    logger.info("Bootstrapped ingestion state to existing OpenSearch latest timestamp %s", last_timestamp)
    return state


def run() -> None:
    ensure_paths()
    state = load_state()
    client = build_client()

    if state.get("last_fetch_timestamp") is None:
        state = bootstrap_initial_state(client, state)
        save_state(state)

    logger.info("Starting ingestion loop with poll interval %s seconds", POLL_INTERVAL_SECONDS)

    while True:
        try:
            docs = fetch_new_documents(client, state)
            if docs:
                normalized: List[Dict[str, Any]] = []
                for hit in docs:
                    source = hit.get("_source", {})
                    event_id = source.get("event_id") or hit.get("_id")
                    if not event_id:
                        continue
                    if event_id in state.get("processed_ids", []):
                        continue
                    try:
                        normalized.append(normalize_event(hit))
                        append_processed_id(state, event_id)
                    except Exception as error:
                        logger.warning("Skipping document %s due to normalization error: %s", hit.get("_id"), error)

                count = write_events(normalized)
                if normalized:
                    last_hit = docs[-1]
                    last_hit_source = last_hit.get("_source", {}) or {}
                    new_ts = last_hit.get("sort", [None])[0] or last_hit_source.get("timestamp")
                    state["last_fetch_timestamp"] = new_ts
                    state["last_sort"] = last_hit.get("sort")
                    save_state(state)
                    logger.info(
                        "Wrote %s normalized events to disk; advanced timestamp to %s",
                        count,
                        state["last_fetch_timestamp"],
                    )
            else:
                logger.info("No new documents found after %s", state.get("last_fetch_timestamp"))

        except (OpenSearchConnectionError, TransportError) as error:
            logger.error("OpenSearch connection failed: %s", error)
            logger.info("Retrying connection after %s seconds", RETRY_BACKOFF_SECONDS)
            time.sleep(RETRY_BACKOFF_SECONDS)
            client = build_client()
            continue
        except Exception as error:
            logger.exception("Unexpected ingestion error: %s", error)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run()
