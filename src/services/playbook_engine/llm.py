import os
import requests
import logging

LOGGER = logging.getLogger("playbook_engine.llm")

# Pointing to the Ollama container running locally
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://172.21.0.2:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral:latest")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "30"))

def enhance_with_llm(playbook: dict, event: dict, mitre: dict, risk: dict) -> dict:
    event_type = event.get('event_type', 'unknown')
    src_ip = event.get('source_ip', 'unknown')
    dst_ip = event.get('destination_ip', 'unknown')
    user = event.get('user', 'unknown')
    mitre_id = mitre.get('technique_id', 'unknown')
    mitre_name = mitre.get('technique_name', 'unknown')
    mitre_tactic = mitre.get('tactic', 'unknown')
    risk_level = risk.get('level', 'medium')
    
    prompt = f"""You are a SOC Analyst. Generate a detailed incident summary for this security event.

EVENT DETAILS:
- Event Type: {event_type}
- Source IP: {src_ip}
- Destination IP: {dst_ip}
- Affected User: {user}
- Timestamp: {event.get('timestamp', 'unknown')}

THREAT INTELLIGENCE:
- MITRE Technique: {mitre_id} ({mitre_name})
- Attack Tactic: {mitre_tactic}
- MITRE Confidence: {mitre.get('confidence', 0.8) * 100:.0f}%

RISK ASSESSMENT:
- Severity: {risk_level}
- Risk Score: {risk.get('score', 50):.0f}/100

Generate a professional incident summary (2-3 sentences) and analyst guidance (2-3 sentences) that explains:
1. What happened and the attack vector
2. Why this is concerning and potential impact
3. Recommended immediate actions

Format the response as:
SUMMARY: <2-3 sentence incident summary>
GUIDANCE: <2-3 sentence analyst guidance>
"""
    
    try:
        response = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=OLLAMA_TIMEOUT)
        
        if response.status_code == 200:
            result = response.json()
            llm_response = result.get("response", "").strip()
            
            summary_lines = [l for l in llm_response.split('\n') if l.startswith('SUMMARY:')]
            guidance_lines = [l for l in llm_response.split('\n') if l.startswith('GUIDANCE:')]
            
            if summary_lines:
                playbook["incident_summary"] = summary_lines[0].replace('SUMMARY:', '').strip()
            if guidance_lines:
                playbook["analyst_guidance"] = guidance_lines[0].replace('GUIDANCE:', '').strip()
            
            if not summary_lines:
                playbook["incident_summary"] = llm_response[:500]
            
            LOGGER.info(f"playbook_id={playbook.get('playbook_id')} LLM enhancement successful")
        else:
            playbook["incident_summary"] = f"LLM returned status code {response.status_code}. Rule-based playbook applied."
            LOGGER.warning(f"playbook_id={playbook.get('playbook_id')} LLM returned {response.status_code}")
    except requests.exceptions.Timeout:
        LOGGER.warning(f"Ollama timeout after {OLLAMA_TIMEOUT}s - using rule-based playbook")
        playbook["incident_summary"] = f"LLM timeout. Rule-based playbook applied."
    except Exception as e:
        LOGGER.warning(f"Ollama enhancement failed: {e}")
        playbook["incident_summary"] = "LLM enhancement unavailable. Offline rule-based playbook applied."
        
    return playbook