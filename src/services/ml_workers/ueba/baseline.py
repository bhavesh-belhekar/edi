import logging
from typing import Dict, Any
from datetime import datetime, timezone

LOGGER = logging.getLogger("ml_workers.ueba")

# Known baseline patterns for user behavior
USER_BASELINES = {
    "admin": {"typical_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18], "typical_days": [1, 2, 3, 4, 5]},
    "root": {"typical_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17], "typical_days": [1, 2, 3, 4, 5]},
    "svc_": {"typical_hours": [0, 1, 2, 3, 4, 5, 6, 22, 23], "typical_days": [1, 2, 3, 4, 5, 6, 7]},
}

def check_ueba(event: Dict[str, Any], features: Dict[str, float]) -> Dict[str, Any]:
    """Compare against user baselines to detect abnormal behavior."""
    ueba_score = 0.3  # Default baseline
    
    user_info = event.get("user", {})
    username = user_info.get("username", "") if isinstance(user_info, dict) else ""
    
    # Check for privileged users
    is_privileged = username.startswith("admin") or username.startswith("root") or "_svc" in username
    
    # Time-based analysis
    current_hour = datetime.now(timezone.utc).hour
    current_day = datetime.now(timezone.utc).weekday()
    
    # Service accounts expected at odd hours
    if username.startswith("svc_"):
        if current_hour in [0, 1, 2, 3, 4, 5, 22, 23]:
            ueba_score = 0.4  # Expected behavior
        else:
            ueba_score = 0.7  # Unusual for service account
    
    # Admin accounts expected during business hours
    elif is_privileged:
        if 8 <= current_hour <= 18 and current_day < 5:
            ueba_score = 0.3  # Normal
        else:
            ueba_score = 0.85  # Unusual privileged activity
    
    # Regular users - default baseline
    else:
        if 8 <= current_hour <= 20 and current_day < 5:
            ueba_score = 0.35
        else:
            ueba_score = 0.65
    
    # Check for odd_hour_activity in features
    if features.get("odd_hour_activity", False):
        ueba_score += 0.2
    
    if features.get("high_frequency", False):
        ueba_score += 0.15
    
    ueba_score = min(max(ueba_score, 0.0), 1.0)
    
    behavioral_risk = "low"
    if ueba_score > 0.7:
        behavioral_risk = "high"
    elif ueba_score > 0.5:
        behavioral_risk = "medium"
    
    LOGGER.info(f"event_id={event.get('event_id','unknown')} ueba_score={ueba_score:.2f} risk={behavioral_risk}")
    
    return {
        "score": ueba_score,
        "behavioral_risk": behavioral_risk
    }
