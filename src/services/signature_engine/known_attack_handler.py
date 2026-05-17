"""
Known Attack Path — fast-path response for previously seen attack patterns.

When the Signature Engine finds a fingerprint match, this handler populates
the SecurityEvent with the stored MITRE mapping, risk score, and playbook
reference so the event can skip the heavy ML/UEBA/Correlation pipeline
(Modules 7–11) and go directly to PostgreSQL storage and the API layer.
"""

from shared.logger import get_logger
from shared.schemas import SecurityEvent

from .store import StoredSignature

logger = get_logger("signature.known_attack")


def apply_known_attack(
    event: SecurityEvent, signature: StoredSignature
) -> SecurityEvent:
    """Stamp the event with all pre-computed analysis from the store."""

    # Mark as signature-matched (Fast Path)
    event.detection.signature_match = True
    event.detection.risk_score = signature.risk_score
    event.detection.risk_level = signature.risk_level

    # Apply stored MITRE ATT&CK mapping
    if signature.mitre_technique_id is not None:
        event.mitre_attack.technique_id = signature.mitre_technique_id
        event.mitre_attack.technique_name = signature.mitre_technique_name
        event.mitre_attack.tactic = signature.mitre_tactic
        event.mitre_attack.confidence = signature.mitre_confidence

    # Attach the pre-existing playbook
    if signature.playbook_id is not None:
        event.playbook.playbook_id = signature.playbook_id
        event.playbook.generated = True
        event.playbook.status = "active"

    logger.info(
        "known attack applied: event_id=%s fingerprint=%s "
        "mitre=%s risk=%s playbook=%s",
        event.event_id,
        signature.fingerprint[:16],
        signature.mitre_technique_id,
        signature.risk_level,
        signature.playbook_id,
    )

    return event
