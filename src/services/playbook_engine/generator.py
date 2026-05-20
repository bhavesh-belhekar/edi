from typing import Dict, Any

def generate_playbook(event: Dict[str, Any], risk_result: Dict[str, Any], mitre_result: Dict[str, Any] = None) -> Dict[str, Any]:
    """Generate rule-based remediation playbooks and analyst guidance."""
    tech_id = mitre_result.get("technique_id") if mitre_result else None
    tech_name = mitre_result.get("technique_name", "Unknown") if mitre_result else "Unknown"
    
    playbook = {
        "playbook_id": f"pb-{event.get('event_id', 'unknown')}",
        "generated": True,
        "status": "generated",
        "incident_summary": "",
        "recommended_actions": [],
        "containment_steps": [],
        "investigation_steps": [],
        "severity": risk_result.get("level", "LOW"),
        "remediation_steps": [],
        "analyst_guidance": "",
    }

    if tech_id == "T1110":
        playbook["containment_steps"] = ["Block attacker IP", "Lock targeted account"]
        playbook["investigation_steps"] = ["Review authentication logs", "Check for successful logins"]
        playbook["recommended_actions"] = ["Enable MFA"]
        playbook["remediation_steps"] = [
            "1. Block attacker IP at firewall/IDS",
            "2. Lock targeted user account immediately",
            "3. Review authentication logs for other failed attempts",
            "4. Check if any successful login occurred from attacker IP",
            "5. Force password reset for affected accounts",
            "6. Enable multi-factor authentication"
        ]
        playbook["analyst_guidance"] = f"Brute force attack detected (T1110). Attacker attempting to guess passwords. Recommended immediate account lockout and IP blocking."
    elif tech_id == "T1078":
        playbook["containment_steps"] = ["Rotate credentials"]
        playbook["investigation_steps"] = ["Verify account owner", "Audit lateral movement"]
        playbook["recommended_actions"] = ["Check privilege escalation"]
        playbook["remediation_steps"] = [
            "1. Rotate all credentials for compromised accounts",
            "2. Audit session tokens and cookies",
            "3. Review privileged group membership",
            "4. Check for lateral movement indicators"
        ]
        playbook["analyst_guidance"] = f"Valid account compromise detected (T1078). Attacker used legitimate credentials. Investigate lateral movement."
    elif tech_id == "T1059":
        playbook["containment_steps"] = ["Isolate endpoint", "Kill suspicious process"]
        playbook["investigation_steps"] = ["Collect forensic evidence", "Scan for persistence"]
        playbook["recommended_actions"] = ["Reimage machine if compromised"]
        playbook["remediation_steps"] = [
            "1. Isolate affected endpoint from network",
            "2. Kill suspicious processes",
            "3. Collect memory and disk forensics",
            "4. Scan for persistence mechanisms",
            "5. Reimage if needed"
        ]
        playbook["analyst_guidance"] = f"Command and script interpreter attack (T1059). Suspicious shell execution detected. Endpoint isolation recommended."
    else:
        playbook["containment_steps"] = ["Isolate affected systems"]
        playbook["investigation_steps"] = ["Review recent logs"]
        playbook["recommended_actions"] = ["Assess security controls"]
        playbook["remediation_steps"] = [
            "1. Isolate affected systems",
            "2. Review recent security logs",
            "3. Assess current security controls",
            "4. Implement additional monitoring"
        ]
        playbook["analyst_guidance"] = f"Unknown attack pattern detected. MITRE technique: {tech_id}. General containment recommended."
        
    return playbook
