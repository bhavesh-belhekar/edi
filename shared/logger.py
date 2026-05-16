import logging
import sys
from typing import Any
from .config import settings

def setup_logger(name: str) -> logging.Logger:
    """
    UNIFIED LOGGING SYSTEM.
    
    Creates a standardized logger for all microservices. 
    In an enterprise SOC environment, structured logging is critical.
    While this uses standard Python logging format initially, it establishes 
    the boundaries needed to easily swap to pythonjsonlogger 
    when we move to ELK/Datadog ingestion.
    """
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers if logger already initialized
    if getattr(logger, '_custom_configured', False):
        return logger

    # Map string log level from config to standard logging levels
    log_level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    level = log_level_map.get(settings.LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(level)

    # Console Handler with standardized formatting
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    # Format: [TIMESTAMP] [LEVEL] [MODULE] - MESSAGE
    # This predictability ensures automated systems can parse terminal stdout
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | [%(name)s] : %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ"
    )
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.propagate = False # Prevent bubbling up to the root logger
    
    # Mark as configured
    setattr(logger, '_custom_configured', True)
    
    return logger
