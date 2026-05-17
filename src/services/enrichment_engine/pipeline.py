"""
Module 5 — Log Enrichment Engine Pipeline.

Chains IP, user, temporal, and context enrichment stages in sequence.
Each stage mutates the SecurityEvent in-place and returns it so the
pipeline reads as a simple linear flow.

Input:  normalized SecurityEvent from the Ingestion Service (Module 4).
Output: enriched SecurityEvent ready for the Signature Engine (Module 6).
"""

from shared.logger import get_logger
from shared.schemas import SecurityEvent

from .ip_enricher import enrich_ip
from .user_enricher import enrich_user
from .time_enricher import enrich_time
from .context_tagger import enrich_context

logger = get_logger("enrichment.pipeline")


def enrich_event(event: SecurityEvent) -> SecurityEvent:
    """Run all enrichment stages on a single event."""
    event = enrich_ip(event)
    event = enrich_user(event)
    event = enrich_time(event)
    event = enrich_context(event)

    logger.info(
        "enriched event_id=%s type=%s severity=%s",
        event.event_id,
        event.event_type,
        event.severity,
    )
    return event
