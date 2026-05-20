from typing import Dict, Any

def extract_features(event: Dict[str, Any]) -> Dict[str, float]:
    """Generate ML features like frequency, failures, time deviation."""
    return {
        "login_frequency": 0.0,
        "failed_attempts": 0.0,
        "time_deviation": 0.0,
        "ip_rarity": 0.0,
        "domain_entropy": 0.0
    }
