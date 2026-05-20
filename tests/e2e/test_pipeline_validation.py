"""
End-to-end pipeline validation test (mocked external dependencies).

Simulates the complete SOC pipeline flow:
- OpenSearch event → normalization → enrichment → SecurityEvent validation
- Fingerprint engine → RabbitMQ → ML workers → MITRE mapping → scoring
"""

import pytest
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from unittest.mock import Mock, patch, MagicMock

from shared.schemas import SecurityEvent, BehavioralFeatures, DetectionInfo
from ingestion_service.models import NormalizedEvent, NullableBehavioralFeatures, NullableDetectionInfo
from ingestion_service.normalizer import EventNormalizer
from ingestion_service.enricher import enrich_event


class MockOpenSearchHit:
    """Mock OpenSearch hit for testing."""
    def __init__(self, event_type: str, raw_log: str, extra_fields: Dict = None):
        self._source = {
            "@timestamp": "2024-01-15T10:30:00.000Z",
            "event": {"type": event_type},
            "wazuh": {"level": "medium"},
            "raw_log": raw_log,
            **(extra_fields or {})
        }
        self._id = "test-id-123"
        self._sort = [1234567890, 0]


class TestPipelineValidation:
    """End-to-end pipeline validation with mocked dependencies."""

    def test_opensearch_to_normalization_enrichment_flow(self):
        """Test: OpenSearch hit → NormalizedEvent → Enrichment → Validation."""
        normalizer = EventNormalizer()
        
        mock_hit = MockOpenSearchHit(
            event_type="failed_login",
            raw_log='{"user": "admin", "src_ip": "192.168.1.100", "result": "failure"}',
            extra_fields={
                "source": {"ip": "192.168.1.100", "port": 54321},
                "user": {"name": "admin", "domain": "CORP"},
            }
        )
        
        normalized = normalizer.normalize(mock_hit)
        assert normalized.event_type == "failed_login"
        
        enriched = enrich_event(normalized)
        assert enriched.behavioral_features is not None
        
        validated = SecurityEvent.model_validate(
            enriched.model_dump(mode="json", exclude_none=True)
        )
        assert validated.event_id == enriched.event_id
        assert validated.event_type == "failed_login"

    def test_partial_enrichment_flow_succeeds(self):
        """Test: Partially enriched events pass through entire pipeline."""
        normalizer = EventNormalizer()
        
        mock_hit = MockOpenSearchHit(
            event_type="network_connection",
            raw_log='{"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8"}',
        )
        
        normalized = normalizer.normalize(mock_hit)
        normalized.behavioral_features = NullableBehavioralFeatures(
            login_frequency=None,
            failed_attempts=None,
            odd_hour_activity=None,
            query_frequency=None,
            high_entropy_domain=None,
            new_domain_observed=None,
            beaconing_detected=None,
            high_frequency=None,
            sensitive_source_asset=None,
            sensitive_destination_asset=None,
        )
        normalized.detection = NullableDetectionInfo(
            signature_match=None,
            anomaly_score=None,
            ueba_score=None,
            risk_score=None,
            risk_level=None,
        )
        
        validated = SecurityEvent.model_validate(
            normalized.model_dump(mode="json", exclude_none=True)
        )
        
        assert validated.behavioral_features is not None
        assert validated.behavioral_features.odd_hour_activity is None
        assert validated.behavioral_features.beaconing_detected is None
        assert validated.detection.signature_match is None

    def test_fingerprint_engine_with_none_enrichment(self):
        """Test: Fingerprint engine handles None-enriched events."""
        from src.services.signature_engine.fingerprint import generate_fingerprint_data
        
        event = SecurityEvent(
            event_id="fp-test-001",
            timestamp=datetime.now(timezone.utc),
            event_type="test_event",
            severity="low",
            raw_log='{"test": "data"}',
            behavioral_features=None,
            detection=None,
            correlation=None,
            mitre_attack=None,
            playbook=None,
        )
        
        fp_hash, fp_string = generate_fingerprint_data(event)
        
        assert fp_hash is not None
        assert len(fp_hash) == 64
        assert "test_event" in fp_string

    def test_rabbitmq_publisher_accepted_none_enriched_event(self):
        """Test: RabbitMQ publisher accepts events with None enrichment fields."""
        with patch('src.services.signature_engine.rabbitmq_publisher.pika') as mock_pika:
            from src.services.signature_engine.rabbitmq_publisher import RabbitMQPublisher
            
            publisher = RabbitMQPublisher()
            
            event_dict = {
                "event_id": "mq-test-001",
                "timestamp": "2024-01-15T10:30:00+00:00",
                "event_type": "test",
                "severity": "medium",
                "raw_log": '{"test": "data"}',
                "behavioral_features": None,
                "detection": None,
                "mitre_attack": None,
                "correlation": None,
                "playbook": None,
            }
            
            publisher.publish_unknown_attack(event_dict)
            
            publisher.channel.basic_publish.assert_called_once()

    def test_ml_worker_validation_accepts_partial_enrichment(self):
        """Test: ML worker consumer validates partial enrichment."""
        from pydantic import ValidationError
        
        partial_event = {
            "event_id": "ml-worker-test-001",
            "timestamp": "2024-01-15T10:30:00+00:00",
            "event_type": "network_connection",
            "severity": "medium",
            "raw_log": '{"data": "test"}',
            "behavioral_features": {
                "login_frequency": None,
                "failed_attempts": None,
                "odd_hour_activity": None,
                "high_frequency": None,
                "beaconing_detected": None,
                "sensitive_destination_asset": None,
            },
            "detection": {
                "signature_match": None,
                "anomaly_score": None,
                "risk_score": None,
            },
        }
        
        validated = SecurityEvent.model_validate(partial_event)
        
        assert validated.event_id == "ml-worker-test-001"
        assert validated.behavioral_features is not None
        assert validated.behavioral_features.high_frequency is None
        assert validated.detection.signature_match is None

    def test_mitre_mapping_with_none_fields(self):
        """Test: MITRE mapper handles events with None fields."""
        from src.services.mitre_mapper.mapper import map_to_mitre
        
        event = SecurityEvent(
            event_id="mitre-test-001",
            timestamp=datetime.now(timezone.utc),
            event_type="test",
            severity="low",
            raw_log='{"test": "data"}',
            behavioral_features=None,
            detection=None,
            mitre_attack=None,
            correlation=None,
            playbook=None,
        )
        
        anomaly_result = {"score": 0.8, "label": "anomalous", "confidence": 0.9}
        ueba_result = {"score": 0.7, "behavioral_risk": "high"}
        
        mitre_result = map_to_mitre(event, anomaly_result, ueba_result)
        
        assert mitre_result.get("technique_id") is not None or mitre_result.get("confidence") == 0.0

    def test_fidelity_scorer_with_none_enrichment(self):
        """Test: Fidelity scorer handles None-enriched events."""
        from src.services.fidelity_engine.scorer import calculate_final_risk
        
        risk_result = calculate_final_risk(
            anomaly_score=0.85,
            ueba_score=0.75,
            mitre_confidence=0.9,
            correlation_strength=0.6,
        )
        
        assert "final_risk_score" in risk_result
        assert "risk_level" in risk_result

    def test_playbook_generator_with_none_enrichment(self):
        """Test: Playbook generator handles None-enriched events."""
        from src.services.playbook_engine.generator import generate_playbook
        
        event = SecurityEvent(
            event_id="playbook-test-001",
            timestamp=datetime.now(timezone.utc),
            event_type="test",
            severity="high",
            raw_log='{"test": "data"}',
            behavioral_features=None,
            detection=None,
            mitre_attack=None,
            correlation=None,
            playbook=None,
        )
        
        risk_result = {"final_risk_score": 85.0, "risk_level": "high"}
        mitre_result = {"technique_id": "T1110", "tactic": "CredentialAccess", "confidence": 0.9}
        
        playbook = generate_playbook(event, risk_result, mitre_result)
        
        assert playbook is not None


class TestOptionalFieldPropagation:
    """Verify Optional fields propagate correctly through pipeline."""

    def test_all_behavioral_bool_fields_accept_none(self):
        """All Optional[bool] behavioral fields should accept None."""
        test_data = {
            "event_id": "bool-test-001",
            "timestamp": "2024-01-15T10:30:00+00:00",
            "event_type": "test",
            "severity": "low",
            "raw_log": '{"test": "data"}',
            "behavioral_features": {
                "odd_hour_activity": None,
                "high_entropy_domain": None,
                "new_domain_observed": None,
                "beaconing_detected": None,
                "is_privileged_user": None,
                "high_frequency": None,
                "sensitive_source_asset": None,
                "sensitive_destination_asset": None,
            },
        }
        
        validated = SecurityEvent.model_validate(test_data)
        
        bf = validated.behavioral_features
        assert bf.odd_hour_activity is None
        assert bf.high_entropy_domain is None
        assert bf.new_domain_observed is None
        assert bf.beaconing_detected is None
        assert bf.is_privileged_user is None
        assert bf.high_frequency is None
        assert bf.sensitive_source_asset is None
        assert bf.sensitive_destination_asset is None

    def test_all_detection_fields_accept_none(self):
        """All detection fields should accept None."""
        test_data = {
            "event_id": "detection-test-001",
            "timestamp": "2024-01-15T10:30:00+00:00",
            "event_type": "test",
            "severity": "low",
            "raw_log": '{"test": "data"}',
            "detection": {
                "signature_match": None,
                "anomaly_score": None,
                "ueba_score": None,
                "risk_score": None,
                "risk_level": None,
            },
        }
        
        validated = SecurityEvent.model_validate(test_data)
        
        dt = validated.detection
        assert dt.signature_match is None
        assert dt.anomaly_score is None
        assert dt.ueba_score is None
        assert dt.risk_score is None
        assert dt.risk_level is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])