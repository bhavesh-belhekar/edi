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

from .fingerprint import generate_fingerprint_data
from .known_attack_handler import apply_known_attack
from .database import FingerprintDB
from .rabbitmq_publisher import RabbitMQPublisher

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
    event: SecurityEvent, db: FingerprintDB, publisher: RabbitMQPublisher
) -> MatchResult:
    """Generate fingerprint, look up PostgreSQL, and route the event."""

    fingerprint_hash, fingerprint_string = generate_fingerprint_data(event)

    stored = db.check_fingerprint(fingerprint_hash)

    # Debug logging for fingerprint details
    src_ip = event.source.ip if event.source else "N/A"
    dst_ip = event.destination.ip if event.destination else "N/A"
    user = event.user.username if event.user and event.user.username else "N/A"
    chain = event.correlation.attack_chain_id if event.correlation and event.correlation.attack_chain_id else "N/A"
    
    if stored is not None and stored.get("known_attack") is True:
        db.update_fingerprint_seen(stored["id"])
        
        logger.info(
            "event_id=%s classification=KNOWN fingerprint=%s reason=matched_in_db "
            "event_type=%s src_ip=%s dst_ip=%s user=%s chain=%s",
            event.event_id,
            fingerprint_hash[:16],
            event.event_type,
            src_ip,
            dst_ip,
            user,
            chain[:20] if chain != "N/A" else "N/A",
        )
        return MatchResult(
            event=event,
            classification=AttackClassification.KNOWN,
            fingerprint=fingerprint_hash,
        )

    # New attack — store the fingerprint and publish to RabbitMQ
    if stored is None:
        db.store_new_fingerprint(fingerprint_hash, fingerprint_string)
        logger.info(
            "event_id=%s classification=NEW fingerprint=%s reason=new_pattern_stored "
            "event_type=%s src_ip=%s dst_ip=%s user=%s",
            event.event_id,
            fingerprint_hash[:16],
            event.event_type,
            src_ip,
            dst_ip,
            user,
        )
    else:
        logger.info(
            "event_id=%s classification=NEW fingerprint=%s reason=not_known_attack "
            "event_type=%s src_ip=%s dst_ip=%s user=%s",
            event.event_id,
            fingerprint_hash[:16],
            event.event_type,
            src_ip,
            dst_ip,
            user,
        )

    # Publish to RabbitMQ queue: unknown_attack_events
    publisher.publish_unknown_attack(event.model_dump(mode="json"))

    return MatchResult(
        event=event,
        classification=AttackClassification.NEW,
        fingerprint=fingerprint_hash,
    )
