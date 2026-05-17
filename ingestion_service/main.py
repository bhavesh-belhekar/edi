"""
Python Ingestion Service (Module 4 + Modules 5 & 6 Integration)

Responsibilities:
1. Fetch NEW normalized events from OpenSearch (Module 4)
2. Apply Log Enrichment (Module 5):
   - IP classification (internal/external)
   - User role/department tagging
   - Odd-hour activity detection
   - Context-based severity escalation
3. Apply Signature/Fingerprint Engine (Module 6):
   - Generate fingerprints from enriched events
   - Match against known attack patterns
4. Route events:
   - KNOWN ATTACKS → PostgreSQL (fast-path, skip ML)
   - NEW ATTACKS → RabbitMQ (forward to Module 7+ workers)
5. Maintain checkpoints for idempotent processing
"""

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List

import psycopg2
from opensearchpy import OpenSearch
import pika

# Add app root to path for imports
import sys
sys.path.insert(0, '/app')

from src.services.enrichment_engine import enrich_event
from src.services.signature_engine import match_event, AttackClassification, SignatureStore
from shared.schemas import SecurityEvent, SourceInfo, DestinationInfo, BehavioralFeatures
from shared.logger import get_logger

logger = get_logger("ingestion.service")

# ============================================================================
# ENVIRONMENT CONFIGURATION
# ============================================================================

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "wazuh.indexer")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
OPENSEARCH_USERNAME = os.getenv("OPENSEARCH_USERNAME", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")
OPENSEARCH_INDEX_PATTERN = os.getenv("OPENSEARCH_INDEX_PATTERN", "wazuh-alerts-*")

POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "5"))
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "200"))
REQUEST_TIMEOUT_SECONDS = int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))

CHECKPOINT_PATH = os.getenv("CHECKPOINT_PATH", "/app/state/checkpoint.json")
OUTPUT_PATH = os.getenv("OUTPUT_PATH", "/app/logs/normalized_events.ndjson")

MAX_RETRIES = int(os.getenv("MAX_RETRIES", "12"))
RETRY_BACKOFF_SECONDS = int(os.getenv("RETRY_BACKOFF_SECONDS", "5"))

# PostgreSQL (known attacks storage)
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgres")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_USER = os.getenv("POSTGRES_USER", "admin")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "admin")
POSTGRES_DB = os.getenv("POSTGRES_DB", "incidents")

# RabbitMQ (new attacks queue)
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "guest")
RABBITMQ_PASSWORD = os.getenv("RABBITMQ_PASSWORD", "guest")
RABBITMQ_QUEUE = os.getenv("RABBITMQ_QUEUE", "ml_pipeline")

# ============================================================================
# GLOBAL STATE
# ============================================================================

SIGNATURE_STORE = None  # Lazy-loaded


def load_signature_store() -> SignatureStore:
    """Initialize and seed the signature store (only once)."""
    global SIGNATURE_STORE
    if SIGNATURE_STORE is None:
        logger.info("Initializing signature store...")
        SIGNATURE_STORE = SignatureStore()
        SIGNATURE_STORE.seed_known_patterns()
    return SIGNATURE_STORE


# ============================================================================
# CHECKPOINT MANAGEMENT
# ============================================================================

def load_checkpoint() -> datetime:
    """Load last processed timestamp from checkpoint file."""
    checkpoint_path = Path(CHECKPOINT_PATH)
    if checkpoint_path.exists():
        try:
            with open(checkpoint_path, "r") as f:
                data = json.load(f)
                ts = data.get("last_timestamp")
                if ts:
                    dt = datetime.fromisoformat(ts)
                    logger.info(f"Loaded checkpoint: {dt.isoformat()}")
                    return dt
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
    
    # Default to 1 hour ago if no checkpoint
    from datetime import timedelta
    default_time = datetime.utcnow() - timedelta(hours=1)
    logger.info(f"No checkpoint found; starting from {default_time.isoformat()}")
    return default_time


def save_checkpoint(timestamp: datetime) -> None:
    """Save the latest processed timestamp to checkpoint file."""
    checkpoint_path = Path(CHECKPOINT_PATH)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(checkpoint_path, "w") as f:
            json.dump({"last_timestamp": timestamp.isoformat()}, f)
        logger.debug(f"Checkpoint saved: {timestamp.isoformat()}")
    except Exception as e:
        logger.error(f"Failed to save checkpoint: {e}")


# ============================================================================
# OPENSEARCH CONNECTION
# ============================================================================

def create_opensearch_client(retries: int = MAX_RETRIES) -> OpenSearch:
    """Create OpenSearch client with retry logic."""
    for attempt in range(retries):
        try:
            client = OpenSearch(
                hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
                http_auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
                use_ssl=False,
                verify_certs=False,
                timeout=REQUEST_TIMEOUT_SECONDS,
                max_retries=3,
                retry_on_timeout=True,
            )
            # Test connection
            info = client.info()
            logger.info(f"Connected to OpenSearch: {info['version']['number']}")
            return client
        except Exception as e:
            logger.warning(f"OpenSearch connection attempt {attempt+1}/{retries} failed: {e}")
            if attempt < retries - 1:
                time.sleep(RETRY_BACKOFF_SECONDS)
            else:
                raise


def fetch_events_from_opensearch(
    client: OpenSearch, last_timestamp: datetime, batch_size: int = BATCH_SIZE
) -> List[dict]:
    """
    Fetch new events from OpenSearch using timestamp filtering.
    Returns raw Wazuh alert documents.
    """
    query = {
        "bool": {
            "must": [{"range": {"timestamp": {"gte": last_timestamp.isoformat()}}}]
        }
    }
    
    try:
        response = client.search(
            index=OPENSEARCH_INDEX_PATTERN,
            body={"query": query, "size": batch_size, "sort": [{"timestamp": "asc"}]},
            timeout="30s",
        )
        
        hits = response.get("hits", {}).get("hits", [])
        logger.info(f"Fetched {len(hits)} events from OpenSearch")
        return [hit["_source"] for hit in hits]
    except Exception as e:
        logger.error(f"Error fetching events from OpenSearch: {e}")
        return []


# ============================================================================
# EVENT NORMALIZATION
# ============================================================================

def normalize_wazuh_alert(raw_alert: dict) -> Optional[SecurityEvent]:
    """
    Convert raw Wazuh alert to SecurityEvent schema.
    Handles missing fields gracefully.
    """
    try:
        # Extract core fields with defaults
        event_type = raw_alert.get("rule", {}).get("description", "unknown_event").lower()
        severity_raw = raw_alert.get("rule", {}).get("level", 3)
        
        # Map Wazuh severity (0-15) to our schema (low/medium/high/critical)
        severity_map = {k: "low" for k in range(0, 5)}
        severity_map.update({k: "medium" for k in range(5, 10)})
        severity_map.update({k: "high" for k in range(10, 13)})
        severity_map.update({k: "critical" for k in range(13, 16)})
        severity = severity_map.get(severity_raw, "medium")
        
        # Source info
        source_ip = raw_alert.get("data", {}).get("srcip", "0.0.0.0")
        source_port = raw_alert.get("data", {}).get("srcport", 0)
        source = SourceInfo(ip=source_ip, port=source_port)
        
        # Destination info
        dest_ip = raw_alert.get("data", {}).get("dstip", "0.0.0.0")
        dest_port = raw_alert.get("data", {}).get("dstport", 0)
        destination = DestinationInfo(ip=dest_ip, port=dest_port)
        
        # User info
        username = raw_alert.get("data", {}).get("user", None)
        
        # Behavioral features (initialize with defaults)
        behavioral_features = BehavioralFeatures(
            failed_attempts=raw_alert.get("data", {}).get("failed_attempts", 0),
            login_frequency=raw_alert.get("data", {}).get("login_frequency", 0),
            odd_hour_activity=False,  # Set by enricher
            beaconing_detected=False,
            high_entropy_domain=False,
        )
        
        # Create SecurityEvent
        event = SecurityEvent(
            event_id=raw_alert.get("id", "unknown"),
            timestamp=datetime.fromisoformat(raw_alert.get("timestamp", datetime.utcnow().isoformat())),
            event_type=event_type,
            severity=severity,
            source=source,
            destination=destination,
            user_username=username,
            raw_log=json.dumps(raw_alert),
            behavioral_features=behavioral_features,
        )
        
        return event
    except Exception as e:
        logger.error(f"Error normalizing alert: {e}")
        return None


# ============================================================================
# POSTGRESQL STORAGE (Known Attacks Fast-Path)
# ============================================================================

def get_postgres_connection(retries: int = MAX_RETRIES):
    """Create PostgreSQL connection with retry logic."""
    for attempt in range(retries):
        try:
            conn = psycopg2.connect(
                host=POSTGRES_HOST,
                port=POSTGRES_PORT,
                user=POSTGRES_USER,
                password=POSTGRES_PASSWORD,
                database=POSTGRES_DB,
            )
            logger.info(f"Connected to PostgreSQL: {POSTGRES_DB}")
            return conn
        except Exception as e:
            logger.warning(f"PostgreSQL connection attempt {attempt+1}/{retries} failed: {e}")
            if attempt < retries - 1:
                time.sleep(RETRY_BACKOFF_SECONDS)
            else:
                raise


def store_known_attack(event: SecurityEvent, signature_id: str, postgres_conn) -> None:
    """Store known attack incident in PostgreSQL."""
    try:
        cursor = postgres_conn.cursor()
        
        # Insert incident record
        query = """
            INSERT INTO incidents 
            (event_id, event_type, severity, source_ip, dest_ip, 
             signature_id, mitre_technique, risk_score, timestamp, raw_event)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_id) DO NOTHING;
        """
        
        cursor.execute(
            query,
            (
                event.event_id,
                event.event_type,
                event.severity,
                event.source.ip if event.source else None,
                event.destination.ip if event.destination else None,
                signature_id,
                event.mitre_attack.technique_id if event.mitre_attack else None,
                event.detection.risk_score if event.detection else 0.0,
                event.timestamp,
                json.dumps(json.loads(event.raw_log)),
            ),
        )
        
        postgres_conn.commit()
        logger.info(f"Stored known attack: {event.event_id} → PostgreSQL")
    except Exception as e:
        postgres_conn.rollback()
        logger.error(f"Error storing known attack in PostgreSQL: {e}")


# ============================================================================
# RABBITMQ PUBLISHER (New Attacks Queue)
# ============================================================================

def get_rabbitmq_connection(retries: int = MAX_RETRIES):
    """Create RabbitMQ connection with retry logic."""
    for attempt in range(retries):
        try:
            credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASSWORD)
            parameters = pika.ConnectionParameters(
                host=RABBITMQ_HOST,
                port=RABBITMQ_PORT,
                credentials=credentials,
                connection_attempts=3,
                retry_delay=2,
            )
            connection = pika.BlockingConnection(parameters)
            logger.info(f"Connected to RabbitMQ: {RABBITMQ_HOST}:{RABBITMQ_PORT}")
            return connection
        except Exception as e:
            logger.warning(f"RabbitMQ connection attempt {attempt+1}/{retries} failed: {e}")
            if attempt < retries - 1:
                time.sleep(RETRY_BACKOFF_SECONDS)
            else:
                raise


def publish_new_attack(event: SecurityEvent, rabbitmq_channel) -> None:
    """Publish new attack event to RabbitMQ for ML processing."""
    try:
        # Declare queue (idempotent)
        rabbitmq_channel.queue_declare(queue=RABBITMQ_QUEUE, durable=True)
        
        # Serialize event
        message = json.dumps({
            "event_id": event.event_id,
            "event_type": event.event_type,
            "severity": event.severity,
            "source_ip": event.source.ip if event.source else None,
            "dest_ip": event.destination.ip if event.destination else None,
            "timestamp": event.timestamp.isoformat(),
            "raw_event": json.loads(event.raw_log),
        })
        
        # Publish
        rabbitmq_channel.basic_publish(
            exchange="",
            routing_key=RABBITMQ_QUEUE,
            body=message,
            properties=pika.BasicProperties(delivery_mode=2),  # Persistent
        )
        
        logger.info(f"Published new attack: {event.event_id} → RabbitMQ")
    except Exception as e:
        logger.error(f"Error publishing to RabbitMQ: {e}")


# ============================================================================
# MAIN INGESTION LOOP
# ============================================================================

def main():
    """Main ingestion service loop."""
    logger.info("Starting Ingestion Service with Enrichment & Signature Pipeline...")
    
    # Initialize
    opensearch_client = None
    postgres_conn = None
    rabbitmq_conn = None
    
    try:
        # Load signature store (seeds known patterns)
        store = load_signature_store()
        
        # Connect to services
        opensearch_client = create_opensearch_client()
        postgres_conn = get_postgres_connection()
        rabbitmq_conn = get_rabbitmq_connection()
        rabbitmq_channel = rabbitmq_conn.channel()
        
        # Load checkpoint
        last_checkpoint = load_checkpoint()
        
        # Main loop
        logger.info("Ingestion loop started. Polling OpenSearch...")
        
        while True:
            try:
                # Fetch new events
                raw_alerts = fetch_events_from_opensearch(opensearch_client, last_checkpoint)
                
                if raw_alerts:
                    logger.info(f"Processing {len(raw_alerts)} events...")
                    
                    known_count = 0
                    new_count = 0
                    
                    for raw_alert in raw_alerts:
                        # Normalize
                        event = normalize_wazuh_alert(raw_alert)
                        if not event:
                            continue
                        
                        # Enrich (Module 5)
                        event = enrich_event(event)
                        
                        # Match fingerprint (Module 6)
                        result = match_event(event, store)
                        
                        # Route based on classification
                        if result.classification == AttackClassification.KNOWN:
                            store_known_attack(result.event, result.fingerprint[:16], postgres_conn)
                            known_count += 1
                        else:  # NEW
                            publish_new_attack(result.event, rabbitmq_channel)
                            new_count += 1
                        
                        # Update checkpoint
                        last_checkpoint = event.timestamp
                    
                    # Save checkpoint
                    save_checkpoint(last_checkpoint)
                    
                    logger.info(
                        f"Batch complete: {known_count} known attacks (fast-path) → PostgreSQL, "
                        f"{new_count} new attacks → RabbitMQ"
                    )
                else:
                    logger.debug("No new events; sleeping...")
                
                # Sleep before next poll
                time.sleep(POLL_INTERVAL_SECONDS)
            
            except Exception as e:
                logger.error(f"Error in ingestion loop: {e}", exc_info=True)
                time.sleep(POLL_INTERVAL_SECONDS)
    
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    
    finally:
        # Cleanup
        if opensearch_client:
            opensearch_client.close()
        if rabbitmq_conn:
            rabbitmq_conn.close()
        if postgres_conn:
            postgres_conn.close()
        logger.info("Ingestion service stopped")


if __name__ == "__main__":
    main()
