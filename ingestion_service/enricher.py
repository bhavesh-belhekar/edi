"""In-process enrichment logic for the ingestion service."""

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Optional

from models import NormalizedEvent, NullableBehavioralFeatures, NullableDetectionInfo

LOGGER = logging.getLogger("ingestion_service.enricher")

# Privileged user patterns
_PRIVILEGED_USERS = frozenset({
    "admin", "root", "sysadmin", "administrator", 
    "domain_admin", "dba", "svc_", "system"
})

# Sensitive asset patterns (case-insensitive substring match)
_SENSITIVE_ASSETS = frozenset({
    "prod-db", "auth-gateway", "finance-app", "corp-fileshare",
    "vault", "kms", "secrets", "admin-panel", "root-srv"
})

# In-memory event frequency tracker
_event_frequency = {}


def _is_internal_ip(ip_str: Optional[str]) -> bool:
    """Check if IP is in RFC1918 private ranges or loopback."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def _is_privileged(username: Optional[str]) -> bool:
    """Check if username matches privileged user patterns."""
    if not username:
        return False
    user_lower = username.lower()
    return any(priv in user_lower for priv in _PRIVILEGED_USERS)


def _is_sensitive_asset(hostname: Optional[str]) -> bool:
    """Check if hostname matches sensitive asset patterns."""
    if not hostname:
        return False
    hostname_lower = hostname.lower()
    return any(asset in hostname_lower for asset in _SENSITIVE_ASSETS)


def _is_odd_hour(timestamp: datetime) -> bool:
    """Check if timestamp is outside business hours (08:00-18:00 UTC)."""
    hour = timestamp.hour
    weekday = timestamp.weekday()  # 0=Monday, 6=Sunday
    
    # Outside 08:00-18:00 OR weekend
    return hour < 8 or hour >= 18 or weekday >= 5


def _track_frequency(event_type: str, source_ip: Optional[str], username: Optional[str]) -> int:
    """
    Track event frequency. Increment counter for (event_type, source_ip, username).
    Returns the count for this combination.
    """
    key = (event_type, source_ip, username)
    # Use simple in-memory dict with max size 10k to prevent memory leak
    if len(_event_frequency) > 10000:
        # Clear old entries (in production use LRU cache or Redis)
        _event_frequency.clear()
    
    _event_frequency[key] = _event_frequency.get(key, 0) + 1
    return _event_frequency[key]


def enrich_event(event: NormalizedEvent) -> NormalizedEvent:
    """
    Apply enrichment to a normalized event.
    
    Enrichment strategies:
    1. IP Classification (internal vs external)
    2. Privileged User Detection
    3. Odd Hour Activity Detection
    4. Sensitive Asset Tagging
    5. Event Frequency Tracking
    """
    
    # Ensure behavioral_features exists
    if event.behavioral_features is None:
        event.behavioral_features = NullableBehavioralFeatures()
    
    # Ensure detection exists
    if event.detection is None:
        event.detection = NullableDetectionInfo()
    
    # 1. IP Classification
    if event.source and event.source.ip:
        is_internal = _is_internal_ip(event.source.ip)
        event.behavioral_features.ip_classification = "internal" if is_internal else "external"
        LOGGER.debug("event_id=%s ip_class=%s ip=%s", event.event_id, 
                    event.behavioral_features.ip_classification, event.source.ip)
    
    # 2. Privileged User Detection
    if event.user and event.user.username:
        is_priv = _is_privileged(event.user.username)
        event.behavioral_features.is_privileged_user = is_priv
        if is_priv:
            LOGGER.debug("event_id=%s privileged_user=%s", event.event_id, event.user.username)
    
    # 3. Odd Hour Activity
    is_odd = _is_odd_hour(event.timestamp)
    event.behavioral_features.odd_hour_activity = is_odd
    if is_odd:
        LOGGER.debug("event_id=%s odd_hour_detected hour=%d", event.event_id, event.timestamp.hour)
    
    # 4. Sensitive Asset Tagging
    if event.source and event.source.hostname:
        if _is_sensitive_asset(event.source.hostname):
            event.behavioral_features.sensitive_source_asset = True
            if event.detection:
                event.detection.risk_score = (event.detection.risk_score or 0) + 10
            LOGGER.debug("event_id=%s sensitive_asset_src=%s", event.event_id, event.source.hostname)
    
    if event.destination and event.destination.hostname:
        if _is_sensitive_asset(event.destination.hostname):
            event.behavioral_features.sensitive_destination_asset = True
            if event.detection:
                event.detection.risk_score = (event.detection.risk_score or 0) + 10
            LOGGER.debug("event_id=%s sensitive_asset_dst=%s", event.event_id, event.destination.hostname)
    
    # 5. Event Frequency Tracking
    count = _track_frequency(
        event.event_type,
        event.source.ip if event.source else None,
        event.user.username if event.user else None
    )
    
    if count >= 5:
        event.behavioral_features.high_frequency = True
        if event.detection:
            event.detection.risk_score = (event.detection.risk_score or 0) + 5
        LOGGER.debug("event_id=%s high_frequency count=%d type=%s", event.event_id, count, event.event_type)
    
    # Compute risk level based on risk_score
    if event.detection and event.detection.risk_score:
        if event.detection.risk_score >= 20:
            event.detection.risk_level = "high"
        elif event.detection.risk_score >= 10:
            event.detection.risk_level = "medium"
        else:
            event.detection.risk_level = "low"
    
    return event
