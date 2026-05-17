from shared.logger import get_logger
from shared.schemas import SecurityEvent

logger = get_logger("enrichment.time")

# Business hours: 08:00 – 18:00 UTC (configurable per deployment)
_BUSINESS_HOUR_START = 8
_BUSINESS_HOUR_END = 18

# Weekend days (Saturday=5, Sunday=6)
_WEEKEND_DAYS = frozenset({5, 6})


def _is_odd_hour(hour: int, weekday: int) -> bool:
    """Return True when the event falls outside normal business hours."""
    if weekday in _WEEKEND_DAYS:
        return True
    return hour < _BUSINESS_HOUR_START or hour >= _BUSINESS_HOUR_END


def enrich_time(event: SecurityEvent) -> SecurityEvent:
    """Tag events that occur outside business hours or on weekends."""
    ts = event.timestamp
    hour = ts.hour
    weekday = ts.weekday()

    odd = _is_odd_hour(hour, weekday)
    event.behavioral_features.odd_hour_activity = odd

    logger.debug(
        "event_id=%s hour=%d weekday=%d odd_hour=%s",
        event.event_id,
        hour,
        weekday,
        odd,
    )

    return event
