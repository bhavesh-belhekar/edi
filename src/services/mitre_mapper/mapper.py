import logging
from typing import Dict, Any

LOGGER = logging.getLogger("mitre_mapper")

# MITRE ATT&CK Technique mappings based on event type
MITRE_MAPPINGS = {
    "failed_login": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "base_confidence": 0.85
    },
    "successful_login": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "base_confidence": 0.7
    },
    "process_start": {
        "technique_id": "T1059",
        "technique_name": "Command and Script Interpreter",
        "tactic": "Execution",
        "base_confidence": 0.75
    },
    "file_access": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "base_confidence": 0.65
    },
    "dns_query": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "base_confidence": 0.6
    },
    "proxy_request": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "base_confidence": 0.55
    },
    "firewall_allow": {
        "technique_id": "T1040",
        "technique_name": "Network Sniffing",
        "tactic": "Discovery",
        "base_confidence": 0.4
    },
    "firewall_deny": {
        "technique_id": "T1567",
        "technique_name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "base_confidence": 0.5
    },
    "logout": {
        "technique_id": "T1333",
        "technique_name": "Credentials",
        "tactic": "Collection",
        "base_confidence": 0.3
    },
    "endpoint_event": {
        "technique_id": "T1547",
        "technique_name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "base_confidence": 0.7
    },
}

def map_to_mitre(event: Dict[str, Any], anomaly_result: Dict[str, Any], ueba_result: Dict[str, Any]) -> Dict[str, Any]:
    """Map the analyzed event to MITRE techniques and tactics dynamically."""
    event_type = event.get("event_type", "")
    severity = event.get("severity", "").lower()
    
    # Get mapping based on event type, default to unknown
    mapping = MITRE_MAPPINGS.get(event_type, {
        "technique_id": "T1588",
        "technique_name": "Obtain Capabilities",
        "tactic": "Resource Development",
        "base_confidence": 0.4
    })
    
    # Adjust confidence based on anomaly and UEBA scores
    anomaly_score = anomaly_result.get("score", 0.5)
    ueba_score = ueba_result.get("score", 0.5)
    
    base_conf = mapping.get("base_confidence", 0.5)
    confidence = base_conf
    
    # Boost confidence for high anomaly scores
    if anomaly_score > 0.7:
        confidence += 0.15
    elif anomaly_score > 0.5:
        confidence += 0.05
    
    # Boost confidence for abnormal user behavior
    ueba_risk = ueba_result.get("behavioral_risk", "low")
    if ueba_risk == "high":
        confidence += 0.1
    elif ueba_risk == "medium":
        confidence += 0.05
    
    # Boost for high severity
    if severity in ["critical", "high"]:
        confidence += 0.1
    
    confidence = min(max(confidence, 0.0), 1.0)
    
    LOGGER.info(f"event_id={event.get('event_id','unknown')} technique={mapping['technique_id']} "
                f"tactic={mapping['tactic']} confidence={confidence:.2f}")
    
    return {
        "technique_id": mapping["technique_id"],
        "technique_name": mapping["technique_name"],
        "tactic": mapping["tactic"],
        "confidence": confidence
    }
