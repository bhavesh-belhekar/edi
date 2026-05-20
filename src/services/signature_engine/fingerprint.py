"""
Fingerprint generation for security events.

A fingerprint is a deterministic hash derived from the key observable
fields of an enriched SecurityEvent.  Two events that share the same
fingerprint are considered instances of the same attack pattern.

FINGERPRINT ENTROPY SOURCES:
- event_type, severity
- source.ip, source.geo, source.port
- destination.ip, destination.port, destination.hostname
- user.username
- process.name, process.command_line
- file.file_hash, file.file_path
- correlation.attack_chain_id
- mitre.technique_id, mitre.tactic
- behavioral features (odd_hour, beaconing, high_entropy, etc.)
"""

import hashlib
from typing import List, Optional

from shared.logger import get_logger
from shared.schemas import SecurityEvent

logger = get_logger("signature.fingerprint")


def _collect_features(event: SecurityEvent) -> List[str]:
    """Extract the distinguishing features that define an attack pattern."""
    features: List[str] = []

    # Core event attributes (high entropy)
    features.append(event.event_type)
    features.append(event.severity)

    # Source information (critical for uniqueness)
    if event.source is not None:
        src = event.source
        features.append(src.ip or "no_ip")
        features.append(src.geo or "unknown")
        if src.port:
            features.append(f"src_port_{src.port}")

    # Destination information (critical for uniqueness)
    if event.destination is not None:
        dst = event.destination
        features.append(dst.ip or "no_ip")
        if dst.port:
            features.append(f"dst_port_{dst.port}")
        if dst.hostname:
            features.append(dst.hostname)

    # User information (attack attribution)
    if event.user is not None and event.user.username:
        features.append(f"user_{event.user.username}")

    # Process information (endpoint telemetry)
    if event.process is not None:
        proc = event.process
        if proc.name:
            features.append(f"process_{proc.name}")
        if proc.command_line:
            # Truncate command line to first 100 chars for fingerprint
            cmd_short = proc.command_line[:100] if len(proc.command_line) > 100 else proc.command_line
            features.append(f"cmd_{hashlib.md5(cmd_short.encode()).hexdigest()[:8]}")

    # File information (malware/tactical)
    if event.file is not None:
        f = event.file
        if f.file_hash:
            features.append(f"hash_{f.file_hash}")
        if f.file_path:
            features.append(f"path_{hashlib.md5(f.file_path.encode()).hexdigest()[:8]}")

    # MITRE ATT&CK (attack classification)
    if event.mitre_attack is not None:
        mitre = event.mitre_attack
        if mitre.technique_id:
            features.append(f"mitre_{mitre.technique_id}")
        if mitre.tactic:
            features.append(f"tactic_{mitre.tactic}")

    # Correlation (attack chain tracking)
    if event.correlation is not None and event.correlation.attack_chain_id:
        features.append(f"chain_{event.correlation.attack_chain_id}")

    # Behavioral features (anomaly detection)
    bf = event.behavioral_features
    if bf:
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
        if bf.is_privileged_user:
            features.append("privileged_user")
        if bf.sensitive_source_asset:
            features.append("sensitive_src")
        if bf.sensitive_destination_asset:
            features.append("sensitive_dst")

    return features


def generate_fingerprint_data(event: SecurityEvent) -> tuple[str, str]:
    """Produce both the feature string and SHA-256 hex digest."""
    features = _collect_features(event)
    canonical = "|".join(sorted(features))
    fp = hashlib.sha256(canonical.encode()).hexdigest()

    logger.info(
        "event_id=%s fingerprint=%s features_count=%d",
        event.event_id,
        fp[:16],
        len(features),
    )
    logger.debug(
        "event_id=%s fingerprint_features=%s",
        event.event_id,
        canonical[:200],  # Truncate for log readability
    )
    return fp, canonical


def generate_fingerprint(event: SecurityEvent) -> str:
    """Produce a SHA-256 hex digest that represents the attack pattern."""
    return generate_fingerprint_data(event)[0]
