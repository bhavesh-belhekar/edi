"""
ML Worker consumer for processing unknown attacks from RabbitMQ.
"""

import json
import logging
import os
import pika
import time
import traceback
from typing import Dict, Any
from pydantic import ValidationError, BaseModel

from src.services.ml_workers.preprocessing.cleaner import clean_event
from src.services.ml_workers.features.extractor import extract_features
from src.services.ml_workers.anomaly.detector import detect_anomalies
from src.services.ml_workers.ueba.baseline import check_ueba
from src.services.correlation_engine.correlator import correlate_event
from src.services.mitre_mapper.mapper import map_to_mitre
from src.services.fidelity_engine.scorer import calculate_final_risk
from src.services.playbook_engine.generator import generate_playbook
from src.services.playbook_engine.llm import enhance_with_llm

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOGGER = logging.getLogger("ml_workers.consumer")

class MinimalEvent(BaseModel):
    """Minimal event schema for validation without required raw_log."""
    model_config = {"extra": "allow"}
    event_id: str = "unknown"
    event_type: str = "unknown"
    timestamp: str = ""
    severity: str = "info"
    source: Dict[str, Any] = {}
    destination: Dict[str, Any] = {}
    user: Dict[str, Any] = {}

class UnknownAttackConsumer:
    def __init__(self):
        self.host = os.getenv("RABBITMQ_HOST", "rabbitmq")
        self.port = int(os.getenv("RABBITMQ_PORT", "5672"))
        self.user = os.getenv("RABBITMQ_USER", "admin")
        self.password = os.getenv("RABBITMQ_PASSWORD", "adminpassword")
        self.queue_name = "unknown_attack_events"
        self.dlq_name = "unknown_attack_events_dlq"
        self.max_retries = 3
        
        credentials = pika.PlainCredentials(self.user, self.password)
        parameters = pika.ConnectionParameters(self.host, self.port, '/', credentials)
        
        self.connection = pika.BlockingConnection(parameters)
        self.channel = self.connection.channel()
        
        # Declare dead-letter queue
        self.channel.queue_declare(queue=self.dlq_name, durable=True)
        
        # Check if main queue exists, if so use it as-is to avoid PRECONDITION_FAILED
        try:
            self.channel.queue_declare(queue=self.queue_name, durable=True)
        except Exception:
            # Queue already exists with different config, use it anyway
            pass
        
        self.channel.basic_qos(prefetch_count=1)

    def process_message(self, ch, method, properties, body):
        event_id = None
        retry_count = 0
        
        # Get retry count from message headers
        if properties.headers and 'x-death' in properties.headers:
            for death in properties.headers['x-death']:
                retry_count = death.get('count', 0)
        
        if retry_count >= self.max_retries:
            LOGGER.warning(f"Message exceeded max retries ({self.max_retries}), rejecting to DLQ")
            ch.basic_reject(delivery_tag=method.delivery_tag, requeue=False)
            return
        
        try:
            event = json.loads(body)
            event_id = event.get("event_id", "unknown")
            LOGGER.info(f"Processing unknown attack event: {event_id}")

            # STEP 3 - A: Preprocessing
            cleaned_event = clean_event(event)
            
            # Ensure required fields for SecurityEvent validation
            if not cleaned_event.get("raw_log"):
                cleaned_event["raw_log"] = f"Processed event from RabbitMQ: {event_id}"
            if not cleaned_event.get("timestamp"):
                cleaned_event["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            # STEP 3 - B: Feature Extraction
            features = extract_features(cleaned_event)

            # STEP 3 - C: Anomaly Detection
            anomaly_result = detect_anomalies(cleaned_event, features)

            # STEP 3 - D: UEBA
            ueba_result = check_ueba(cleaned_event, features)

            # STEP 4: Correlation (real implementation)
            correlation_result = correlate_event(cleaned_event)
            LOGGER.info(
                f"event_id={event_id} correlation complete: "
                f"incident_id={correlation_result.get('incident_id')} "
                f"stage={correlation_result.get('attack_chain_stage')} "
                f"related_events={correlation_result.get('related_event_count')} "
                f"confidence={correlation_result.get('correlation_strength'):.2f}"
            )

            # STEP 5: MITRE Mapping
            mitre_result = map_to_mitre(cleaned_event, anomaly_result, ueba_result)

            # STEP 6: Fidelity / Risk Scoring
            risk_result = calculate_final_risk(
                anomaly_score=anomaly_result.get("score", 0.5),
                ueba_score=ueba_result.get("score", 0.5),
                mitre_confidence=mitre_result.get("confidence", 0.5),
                correlation_strength=correlation_result.get("correlation_strength", 0.5)
            )

            # STEP 7: Playbook Generation
            playbook = generate_playbook(cleaned_event, risk_result, mitre_result)
            LOGGER.info(f"event_id={event_id} playbook generated id={playbook.get('playbook_id')} "
                        f"remediation_steps_count={len(playbook.get('remediation_steps', []))}")

            # STEP 14: Ollama LLM Enhancement
            LOGGER.info(f"event_id={event_id} calling Ollama for enhancement...")
            playbook = enhance_with_llm(playbook, cleaned_event, mitre_result, risk_result)
            LOGGER.info(f"event_id={event_id} LLM enhancement complete summary_len={len(playbook.get('incident_summary', ''))}")

            # STEP 8: Store Final Intelligence
            from src.services.signature_engine.database import FingerprintDB
            from src.services.signature_engine.fingerprint import generate_fingerprint_data
            from shared.schemas import SecurityEvent
            
            # Create SecurityEvent with all required fields
            LOGGER.info(f"event_id={event_id} validating event schema...")
            sec_event = SecurityEvent.model_validate(cleaned_event)
            LOGGER.info(f"event_id={event_id} generating fingerprint...")
            fp_hash, fp_string = generate_fingerprint_data(sec_event)
            LOGGER.info(f"event_id={event_id} fingerprint={fp_hash[:16]} storing intelligence")

            LOGGER.info(f"event_id={event_id} connecting to database...")
            db = FingerprintDB()
            # We check first to get the ID, theoretically when generated it was stored
            stored = db.check_fingerprint(fp_hash)
            if stored:
                db.store_final_intelligence(stored['id'], mitre_result, risk_result, playbook)
                LOGGER.info(f"event_id={event_id} stored_in_db fingerprint_id={stored['id']}")
            else:
                # Store new fingerprint with intelligence
                fp_id = db.store_new_fingerprint(fp_hash, fp_string)
                db.store_final_intelligence(fp_id, mitre_result, risk_result, playbook)
                LOGGER.info(f"event_id={event_id} new_fingerprint_stored fp_id={fp_id}")
            db.close()

            ch.basic_ack(delivery_tag=method.delivery_tag)
            LOGGER.info(f"event_id={event_id} processing complete, message ACKed")

        except ValidationError as ve:
            failed_fields = [e["loc"][0] if e["loc"] else "unknown" for e in ve.errors()]
            LOGGER.error(
                "event_id=%s validation failed fields=%s error=%s",
                event_id,
                failed_fields,
                str(ve),
            )
            # ACK the message to prevent infinite retry - log for analysis
            ch.basic_ack(delivery_tag=method.delivery_tag)
            LOGGER.warning(f"event_id={event_id} message ACKed despite validation failure (logged for analysis)")

        except Exception as e:
            LOGGER.error("event_id=%s processing failed: %s\n%s", event_id, str(e), traceback.format_exc())
            # ACK the message to prevent blocking - log for analysis
            ch.basic_ack(delivery_tag=method.delivery_tag)
            LOGGER.warning(f"event_id={event_id} message ACKed despite processing failure (logged for analysis)")

    def start_consuming(self):
        self.channel.basic_consume(queue=self.queue_name, on_message_callback=self.process_message)
        LOGGER.info("Waiting for unknown attack events...")
        self.channel.start_consuming()

if __name__ == "__main__":
    consumer = UnknownAttackConsumer()
    consumer.start_consuming()
