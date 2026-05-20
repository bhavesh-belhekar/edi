from typing import Dict, Any

def calculate_final_risk(anomaly_score: float, ueba_score: float, mitre_confidence: float, correlation_strength: float) -> Dict[str, Any]:
    """Combine scores to calculate final fidelity and risk level."""
    final_score = (anomaly_score + ueba_score + mitre_confidence + correlation_strength) / 4.0
    
    level = "LOW"
    if final_score > 0.85:
        level = "CRITICAL"
    elif final_score > 0.70:
        level = "HIGH"
    elif final_score > 0.50:
        level = "MEDIUM"

    return {
        "final_risk_score": final_score,
        "level": level
    }
