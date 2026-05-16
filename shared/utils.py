import uuid
import json
from datetime import datetime, timezone
from typing import Any, Dict

"""
REUSABLE HELPER UTILITIES.

This file contains ONLY stateless, pure functions.
Business logic (e.g., calculating ML scores, DB queries) MUST NEVER reside here.
"""

def get_utc_now() -> datetime:
    """
    Returns the current timezone-aware UTC datetime.
    Ensures the entire global pipeline operates on a unified temporal baseline.
    """
    return datetime.now(timezone.utc)

def generate_uuid() -> str:
    """
    Generates a standardized UUID4 string for linking events and playbooks.
    """
    return str(uuid.uuid4())

def safe_dict_get(data: Dict[str, Any], keys: list, default: Any = None) -> Any:
    """
    Safely traverses a deeply nested dictionary to extract a value without raising KeyError.
    Example: safe_dict_get(raw_log, ["rule", "mitre", "id"], "Unknown")
    """
    current = data
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current

class CustomJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder to handle dates, UUIDs, and Pydantic models serialization
    safely over RabbitMQ boundaries.
    """
    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, uuid.UUID):
            return str(obj)
        if hasattr(obj, "model_dump"):  # Handle Pydantic V2
            return obj.model_dump()
        return super().default(obj)

def to_json_str(obj: Any) -> str:
    """
    Safely converts objects/dicts to standardized JSON strings using the CustomJSONEncoder.
    """
    return json.dumps(obj, cls=CustomJSONEncoder)
