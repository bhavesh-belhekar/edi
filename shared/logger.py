import logging
import sys
from typing import Optional

from .config import settings


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Create and return a configured logger.

    This function ensures a single configuration is applied per logger name
    and makes the output predictable for log parsing systems.
    """
    logger_name = name or "edi"
    logger = logging.getLogger(logger_name)

    if getattr(logger, "_custom_configured", False):
        return logger

    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    level = level_map.get(getattr(settings, "LOG_LEVEL", "INFO").upper(), logging.INFO)
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | [%(name)s] : %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.propagate = False
    setattr(logger, "_custom_configured", True)

    return logger
