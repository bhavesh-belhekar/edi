"""
PostgreSQL database client for the Signature/Fingerprint Engine.
"""

import json
import logging
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Optional, Dict, Any

LOGGER = logging.getLogger("signature_engine.database")

class FingerprintDB:
    def __init__(self):
        self.conn = psycopg2.connect(
            dbname=os.getenv("POSTGRES_DB", "cyber_intelligence"),
            user=os.getenv("POSTGRES_USER", "admin"),
            password=os.getenv("POSTGRES_PASSWORD", "adminpassword"),
            host=os.getenv("POSTGRES_HOST", "postgres"),
            port=os.getenv("POSTGRES_PORT", "5432")
        )
        self.conn.autocommit = True
    
    def check_fingerprint(self, fingerprint_hash: str) -> Optional[Dict[str, Any]]:
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM fingerprints WHERE fingerprint_hash = %s",
                (fingerprint_hash,)
            )
            return cur.fetchone()

    def update_fingerprint_seen(self, fingerprint_id: int):
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE fingerprints SET match_count = match_count + 1, last_seen = NOW() WHERE id = %s",
                (fingerprint_id,)
            )

    def store_new_fingerprint(self, fingerprint_hash: str, fingerprint_string: str) -> int:
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO fingerprints (fingerprint_hash, fingerprint_string, known_attack)
                VALUES (%s, %s, FALSE)
                RETURNING id
                """,
                (fingerprint_hash, fingerprint_string)
            )
            return cur.fetchone()['id']

    def store_final_intelligence(self, fingerprint_id: int, mitre_data: dict, risk_data: dict, playbook_data: dict):
        """STEP 8 - STORE FINAL INTELLIGENCE"""
        with self.conn.cursor() as cur:
            # Update fingerprint to be a known attack
            cur.execute(
                "UPDATE fingerprints SET known_attack = TRUE, risk_level = %s, mitre_technique_id = %s WHERE id = %s",
                (risk_data.get('level'), mitre_data.get('technique_id'), fingerprint_id)
            )

            # Store MITRE mappings - truncate tactic to fit in VARCHAR(64)
            tactic = mitre_data.get('tactic', '')
            if len(tactic) > 64:
                tactic = tactic[:61] + "..."  # Truncate with ellipsis
            
            cur.execute(
                "INSERT INTO mitre_mappings (fingerprint_id, technique_id, tactic, confidence) VALUES (%s, %s, %s, %s)",
                (fingerprint_id, mitre_data.get('technique_id'), tactic, mitre_data.get('confidence'))
            )

            # Store Risk Scores
            cur.execute(
                "INSERT INTO risk_scores (fingerprint_id, final_risk_score) VALUES (%s, %s)",
                (fingerprint_id, risk_data.get('final_risk_score'))
            )

            # Store Playbook - truncate analyst_guidance if too long
            analyst_guidance = playbook_data.get('analyst_guidance', '')
            if len(analyst_guidance) > 500:
                analyst_guidance = analyst_guidance[:497] + "..."
            
            cur.execute(
                "INSERT INTO playbooks (fingerprint_id, remediation_steps, analyst_guidance) VALUES (%s, %s, %s)",
                (fingerprint_id, json.dumps(playbook_data.get('remediation_steps')), analyst_guidance)
            )

    def close(self):
        self.conn.close()
