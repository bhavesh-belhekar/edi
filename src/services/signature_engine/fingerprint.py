"""
Fingerprint generation for security events.

A fingerprint is a deterministic hash derived from the key observable
fields of an enriched SecurityEvent.  Two events that share the same
fingerprint are considered instances of the same attack pattern.
"""

import hashlib
from typing import List

from shared.logger import get_logger
from shared.schemas import SecurityEvent

logger = get_logger("signature.fingerprint")


def _collect_features(event: SecurityEvent) -> List[str]:
    """Extract the distinguishing features that define an attack pattern."""
    features: List[str] = []

    features.append(event.event_type)
    features.append(event.severity)

    if event.source is not None:
        features.append(event.source.geo or "unknown")

    bf = event.behavioral_features
    if bf.odd_hour_activity:
        features.append("odd_hour")
    if bf.failed_attempts >= 3:
        features.append("repeated_failures")
    if bf.login_frequency >= 5:
        features.append("high_frequency")
    if bf.beaconing_detected:
        features.append("beaconing")
    if bf.high_entropy_domain:
        features.append("high_entropy_domain")

    return features


def generate_fingerprint(event: SecurityEvent) -> str:
    """Produce a SHA-256 hex digest that represents the attack pattern."""
    features = _collect_features(event)
    canonical = "|".join(sorted(features))
    fp = hashlib.sha256(canonical.encode()).hexdigest()

    logger.debug(
        "event_id=%s features=%s fingerprint=%s",
        event.event_id,
        canonical,
        fp[:16],
    )
    return fp
