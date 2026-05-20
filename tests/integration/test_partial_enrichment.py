"""
Integration test: Partial enrichment schema compatibility.

Validates that SecurityEvent accepts events with None-valued enrichment fields,
ensuring the ingestion pipeline can process partially enriched events.
"""

import pytest
from datetime import datetime, timezone

from shared.schemas import SecurityEvent
from ingestion_service.models import NormalizedEvent


class TestPartialEnrichmentValidation:
    """Test that SecurityEvent accepts partially enriched events."""

    def test_validation_succeeds_with_none_enrichment_fields(self):
        """SecurityEvent.model_validate should succeed when enrichment fields are None."""
        normalized = NormalizedEvent(
            event_id="test-event-001",
            timestamp=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
            event_type="test_event",
            severity="medium",
            behavioral_features=None,
            detection=None,
            mitre_attack=None,
            correlation=None,
            playbook=None,
            raw_log='{"test": "raw_log_data"}',
        )

        validated = SecurityEvent.model_validate(
            normalized.model_dump(mode="json", exclude_none=True)
        )

        assert validated.event_id == "test-event-001"
        assert validated.behavioral_features is None
        assert validated.detection is None
        assert validated.mitre_attack is None
        assert validated.correlation is None
        assert validated.playbook is None

    def test_validation_succeeds_with_partial_behavioral_features(self):
        """Validation should pass with some behavioral fields set to None."""
        from ingestion_service.models import NullableBehavioralFeatures

        normalized = NormalizedEvent(
            event_id="test-event-002",
            timestamp=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
            event_type="network_connection",
            severity="low",
            behavioral_features=NullableBehavioralFeatures(
                login_frequency=5,
                failed_attempts=2,
                odd_hour_activity=None,
                high_entropy_domain=None,
                new_domain_observed=None,
                beaconing_detected=None,
                is_privileged_user=None,
                high_frequency=None,
                sensitive_source_asset=None,
                sensitive_destination_asset=None,
            ),
            detection=None,
            mitre_attack=None,
            correlation=None,
            playbook=None,
            raw_log='{"test": "data"}',
        )

        validated = SecurityEvent.model_validate(
            normalized.model_dump(mode="json", exclude_none=True)
        )

        assert validated.behavioral_features is not None
        assert validated.behavioral_features.login_frequency == 5
        assert validated.behavioral_features.odd_hour_activity is None
        assert validated.behavioral_features.high_frequency is None
        assert validated.behavioral_features.beaconing_detected is None
        assert validated.behavioral_features.sensitive_destination_asset is None

    def test_validation_succeeds_with_partial_detection_info(self):
        """Validation should pass with detection fields set to None."""
        from ingestion_service.models import NullableDetectionInfo

        normalized = NormalizedEvent(
            event_id="test-event-003",
            timestamp=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
            event_type="auth_failure",
            severity="high",
            detection=NullableDetectionInfo(
                signature_match=None,
                anomaly_score=None,
                ueba_score=None,
                risk_score=None,
                risk_level=None,
            ),
            behavioral_features=None,
            mitre_attack=None,
            correlation=None,
            playbook=None,
            raw_log='{"test": "data"}',
        )

        validated = SecurityEvent.model_validate(
            normalized.model_dump(mode="json", exclude_none=True)
        )

        assert validated.detection is not None
        assert validated.detection.signature_match is None
        assert validated.detection.anomaly_score is None
        assert validated.detection.risk_score is None

    def test_validation_succeeds_with_all_none_boolean_fields(self):
        """All Optional[bool] enrichment fields should accept None values."""
        from ingestion_service.models import NullableBehavioralFeatures, NullableDetectionInfo

        normalized = NormalizedEvent(
            event_id="test-event-004",
            timestamp=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
            event_type="test",
            severity="info",
            behavioral_features=NullableBehavioralFeatures(
                odd_hour_activity=None,
                high_entropy_domain=None,
                new_domain_observed=None,
                beaconing_detected=None,
                is_privileged_user=None,
                high_frequency=None,
                sensitive_source_asset=None,
                sensitive_destination_asset=None,
            ),
            detection=NullableDetectionInfo(
                signature_match=None,
            ),
            playbook=None,
            correlation=None,
            mitre_attack=None,
            raw_log='{"test": "data"}',
        )

        validated = SecurityEvent.model_validate(
            normalized.model_dump(mode="json", exclude_none=True)
        )

        bf = validated.behavioral_features
        assert bf.odd_hour_activity is None
        assert bf.high_entropy_domain is None
        assert bf.new_domain_observed is None
        assert bf.beaconing_detected is None
        assert bf.high_frequency is None
        assert bf.sensitive_destination_asset is None

        assert validated.detection.signature_match is None

    def test_validation_fails_for_missing_required_fields(self):
        """Validation should still fail for truly required fields."""
        from pydantic import ValidationError

        normalized = NormalizedEvent(
            event_id="test-event-005",
            timestamp=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
            event_type="test",
            severity="info",
            raw_log=None,
        )

        with pytest.raises(ValidationError):
            SecurityEvent.model_validate(
                normalized.model_dump(mode="json", exclude_none=True)
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])