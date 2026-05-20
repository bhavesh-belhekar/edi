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

            # STEP 4: CORRELATION ENGINE - Group events into incidents FIRST
            # This is the KEY step - group related events before playbook generation
            correlation_result = correlate_event(cleaned_event)
            incident_id = correlation_result.get('incident_id', 'unknown')
            related_event_count = correlation_result.get('related_event_count', 0)
            attack_stage = correlation_result.get('attack_chain_stage', 'Unknown')
            confidence = correlation_result.get('correlation_strength', 0.5)
            linked_entities = correlation_result.get('linked_entities', {})
            
            LOGGER.info(
                f"event_id={event_id} correlation complete: "
                f"incident_id={incident_id} "
                f"stage={attack_stage} "
                f"related_events={related_event_count} "
                f"confidence={confidence:.2f}"
            )

            # STEP 5: MITRE Mapping (per incident, not per event)
            mitre_result = map_to_mitre(cleaned_event, anomaly_result, ueba_result)

            # STEP 6: Fidelity / Risk Scoring (per incident)
            risk_result = calculate_final_risk(
                anomaly_score=anomaly_result.get("score", 0.5),
                ueba_score=ueba_result.get("score", 0.5),
                mitre_confidence=mitre_result.get("confidence", 0.5),
                correlation_strength=confidence
            )

            # STEP 7: Playbook Generation - ONLY for NEW incidents
            # Do NOT generate playbooks from raw logs - only from correlated incidents
            from src.services.signature_engine.database import FingerprintDB
            
            db_check = FingerprintDB()
            existing_incident_playbook = db_check.get_incident_playbook(incident_id)
            
            playbook = None
            playbook_action = "skip"
            
            if existing_incident_playbook is None:
                # NEW correlated incident - generate playbook
                playbook = generate_playbook(cleaned_event, risk_result, mitre_result)
                playbook_action = "create"
                LOGGER.info(f"event_id={event_id} NEW correlated incident {incident_id} - generating playbook")
                
                # STEP 14: Ollama Enhancement (only for new playbooks)
                LOGGER.info(f"event_id={event_id} calling Ollama for enhancement...")
                playbook = enhance_with_llm(playbook, cleaned_event, mitre_result, risk_result)
                LOGGER.info(f"event_id={event_id} LLM enhancement complete")
            else:
                # Existing incident - use existing playbook, don't regenerate
                playbook = {
                    "playbook_id": f"pb-{incident_id}",
                    "remediation_steps": existing_incident_playbook.get("remediation_steps", []),
                    "analyst_guidance": existing_incident_playbook.get("analyst_guidance", ""),
                    "incident_summary": f"Correlated incident with {related_event_count} events - using existing playbook"
                }
                LOGGER.info(f"event_id={event_id} existing incident {incident_id} - using existing playbook")
            
            db_check.close()

            # STEP 8: Store Intelligence (fingerprint + incident playbook)
            from src.services.signature_engine.database import FingerprintDB
            from src.services.signature_engine.fingerprint import generate_fingerprint_data
            from shared.schemas import SecurityEvent
            
            LOGGER.info(f"event_id={event_id} validating event schema...")
            sec_event = SecurityEvent.model_validate(cleaned_event)
            LOGGER.info(f"event_id={event_id} generating fingerprint...")
            fp_hash, fp_string = generate_fingerprint_data(sec_event)
            LOGGER.info(f"event_id={event_id} fingerprint={fp_hash[:16]} storing intelligence")

            LOGGER.info(f"event_id={event_id} connecting to database...")
            db = FingerprintDB()
            
            # Store fingerprint
            stored = db.check_fingerprint(fp_hash)
            fingerprint_id = None
            if stored:
                fingerprint_id = stored['id']
                db.store_final_intelligence(stored['id'], mitre_result, risk_result, playbook, event_count=related_event_count + 1)
                LOGGER.info(f"event_id={event_id} fingerprint updated fingerprint_id={stored['id']}")
            else:
                fingerprint_id = db.store_new_fingerprint(fp_hash, fp_string)
                db.store_final_intelligence(fingerprint_id, mitre_result, risk_result, playbook, event_count=1)
                LOGGER.info(f"event_id={event_id} new_fingerprint_stored fp_id={fingerprint_id}")

            # Store incident-based playbook ONLY for new incidents (deduplication)
            if existing_incident_playbook is None:
                linked_fps = [fingerprint_id] if fingerprint_id else []
                db.store_incident_playbook(
                    incident_id=incident_id,
                    event_count=related_event_count + 1,
                    mitre_data=mitre_result,
                    risk_data=risk_result,
                    playbook_data=playbook,
                    linked_fingerprints=linked_fps
                )
                LOGGER.info(f"event_id={event_id} NEW incident_playbook CREATED for {incident_id}")
            else:
                LOGGER.info(f"event_id={event_id} incident_playbook already exists for {incident_id}")
            
            db.close()

            ch.basic_ack(delivery_tag=method.delivery_tag)
            LOGGER.info(f"event_id={event_id} processing complete, message ACKed")

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
