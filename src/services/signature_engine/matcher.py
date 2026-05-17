"""
Module 6 — Signature / Fingerprint Engine Matcher.

This is the primary entry point for Module 6.  It accepts an enriched
SecurityEvent (output of Module 5), generates a fingerprint, and checks
it against the signature store.

Decision logic (per architecture):
  - IF match found  → classify as KNOWN ATTACK, apply stored analysis
  - ELSE            → classify as NEW ATTACK (downstream: RabbitMQ → ML)

Returns a ``MatchResult`` that carries the event and the classification
so the caller can route it to the appropriate path.
"""

from dataclasses import dataclass
from enum import Enum

from shared.logger import get_logger
from shared.schemas import SecurityEvent

from .fingerprint import generate_fingerprint
from .known_attack_handler import apply_known_attack
from .store import SignatureStore, StoredSignature

logger = get_logger("signature.matcher")


class AttackClassification(str, Enum):
    KNOWN = "known"
    NEW = "new"


@dataclass
class MatchResult:
    """Outcome of the signature matching process."""

    event: SecurityEvent
    classification: AttackClassification
    fingerprint: str


def match_event(
    event: SecurityEvent, store: SignatureStore
) -> MatchResult:
    """Generate fingerprint, look up store, and route the event."""

    fingerprint = generate_fingerprint(event)

    stored = store.lookup(fingerprint)

    if stored is not None:
        event = apply_known_attack(event, stored)
        logger.info(
            "event_id=%s → KNOWN ATTACK (fp=%s)",
            event.event_id,
            fingerprint[:16],
        )
        return MatchResult(
            event=event,
            classification=AttackClassification.KNOWN,
            fingerprint=fingerprint,
        )

    # New attack — store the fingerprint for future matches and let the
    # event continue to the heavy-analysis pipeline (RabbitMQ → ML).
    new_sig = StoredSignature(
        fingerprint=fingerprint,
        event_type=event.event_type,
    )
    store.store(new_sig)

    logger.info(
        "event_id=%s → NEW ATTACK (fp=%s)",
        event.event_id,
        fingerprint[:16],
    )
    return MatchResult(
        event=event,
        classification=AttackClassification.NEW,
        fingerprint=fingerprint,
    )
