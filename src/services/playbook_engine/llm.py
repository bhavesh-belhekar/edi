import os
import requests
import logging

LOGGER = logging.getLogger("playbook_engine.llm")

# Pointing to the Ollama container running locally
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "10"))  # Reduced from 120s to 10s to prevent blocking

def enhance_with_llm(playbook: dict, event: dict, mitre: dict, risk: dict) -> dict:
    prompt = f"""
    Analyze this cyber incident and provide a short summary and analyst explanation. Explain the remediation briefly.
    Event Type: {event.get('event_type')}
    MITRE Technique: {mitre.get('technique_id')} - {mitre.get('technique_name')}
    Risk Severity: {risk.get('level')}
    """
    
    try:
        response = requests.post(OLLAMA_URL, json={
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=OLLAMA_TIMEOUT)
        
        if response.status_code == 200:
            result = response.json()
            playbook["incident_summary"] = result.get("response", "").strip()
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