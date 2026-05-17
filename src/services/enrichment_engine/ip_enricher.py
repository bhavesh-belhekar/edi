import ipaddress
from typing import Optional

from shared.logger import get_logger
from shared.schemas import SecurityEvent

logger = get_logger("enrichment.ip")

# RFC 1918 / RFC 6598 private ranges resolved at import time
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]

_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")


def _classify_ip(ip_str: str) -> str:
    """Return 'internal', 'external', 'loopback', or 'link-local'."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown"

    if addr in _LOOPBACK:
        return "loopback"
    if addr in _LINK_LOCAL:
        return "link-local"
    for net in _PRIVATE_NETS:
        if addr in net:
            return "internal"
    return "external"


def _derive_subnet(ip_str: str) -> Optional[str]:
    """Return the /24 subnet for IPv4 or /64 for IPv6."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None

    if isinstance(addr, ipaddress.IPv4Address):
        net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
    else:
        net = ipaddress.ip_network(f"{ip_str}/64", strict=False)
    return str(net)


def enrich_ip(event: SecurityEvent) -> SecurityEvent:
    """Classify source/destination IPs as internal or external and tag geo."""
    if event.source is not None:
        classification = _classify_ip(event.source.ip)
        if event.source.geo is None:
            event.source.geo = classification
        logger.debug(
            "source ip=%s classified=%s", event.source.ip, classification
        )

    if event.destination is not None:
        dest_class = _classify_ip(event.destination.ip)
        if event.destination.hostname is None:
            event.destination.hostname = f"{dest_class}-host"
        logger.debug(
            "destination ip=%s classified=%s",
            event.destination.ip,
            dest_class,
        )

    return event
