from shared.logger import get_logger
from shared.schemas import SecurityEvent

logger = get_logger("enrichment.context")

# Event types that are inherently suspicious
_SUSPICIOUS_EVENT_TYPES = frozenset({
    "failed_login",
    "brute_force",
    "privilege_escalation",
    "lateral_movement",
    "c2_communication",
    "data_exfiltration",
    "suspicious_dns",
    "port_scan",
    "credential_dump",
})

# Thresholds for repeated-attempt detection
_HIGH_FREQUENCY_THRESHOLD = 5
_FAILED_ATTEMPT_THRESHOLD = 3


def enrich_context(event: SecurityEvent) -> SecurityEvent:
    """Apply contextual tags based on event type, frequency, and patterns."""

    is_suspicious_type = event.event_type in _SUSPICIOUS_EVENT_TYPES

    bf = event.behavioral_features
    repeated_attempt = bf.failed_attempts >= _FAILED_ATTEMPT_THRESHOLD
    high_frequency = bf.login_frequency >= _HIGH_FREQUENCY_THRESHOLD

    # Escalate severity for events with multiple risk indicators
    risk_signals = sum([
        is_suspicious_type,
        repeated_attempt,
        high_frequency,
        bf.odd_hour_activity,
        bf.beaconing_detected,
        bf.high_entropy_domain,
    ])

    if risk_signals >= 3 and event.severity in ("info", "low"):
        event.severity = "high"
        logger.info(
            "event_id=%s severity escalated to high (signals=%d)",
            event.event_id,
            risk_signals,
        )
    elif risk_signals >= 2 and event.severity == "info":
        event.severity = "medium"

    logger.debug(
        "event_id=%s suspicious_type=%s repeated=%s high_freq=%s signals=%d",
        event.event_id,
        is_suspicious_type,
        repeated_attempt,
        high_frequency,
        risk_signals,
    )

    return event
