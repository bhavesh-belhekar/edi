import logging
from typing import Dict, Any
from datetime import datetime, timezone

LOGGER = logging.getLogger("ml_workers.anomaly")

def detect_anomalies(event: Dict[str, Any], features: Dict[str, float]) -> Dict[str, Any]:
    """Detect anomalies using statistical methods and baselines."""
    anomaly_score = 0.5
    
    # Calculate anomaly based on event characteristics
    severity = event.get("severity", "").lower()
    event_type = event.get("event_type", "")
    
    # Higher severity events get higher anomaly scores
    if severity in ["critical", "high"]:
        anomaly_score = 0.85
    elif severity == "medium":
        anomaly_score = 0.6
    elif severity in ["low", "info"]:
        anomaly_score = 0.35
    
    # Type-based scoring
    if event_type in ["failed_login", "brute_force", "suspicious_process"]:
        anomaly_score = max(anomaly_score, 0.8)
    elif event_type in ["successful_login", "firewall_allow", "dns_query"]:
        anomaly_score = min(anomaly_score, 0.4)
    
    # Feature-based adjustment
    if features.get("login_frequency", 0) > 10:
        anomaly_score += 0.1
    if features.get("failed_attempts", 0) > 5:
        anomaly_score += 0.15
    
    anomaly_score = min(max(anomaly_score, 0.0), 1.0)
    
    label = "normal"
    if anomaly_score > 0.7:
        label = "anomalous"
    elif anomaly_score > 0.5:
        label = "suspicious"
    
    confidence = 0.75 + (anomaly_score * 0.2)
    
    LOGGER.info(f"event_id={event.get('event_id','unknown')} anomaly_score={anomaly_score:.2f} label={label}")
    
    return {
        "score": anomaly_score,
        "label": label,
        "confidence": confidence
    }
