"""
PostgreSQL database client for the Signature/Fingerprint Engine.
"""

import json
import logging
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Optional, Dict, Any, List

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
        self._ensure_incident_playbooks_table()

    def _ensure_incident_playbooks_table(self):
        """Ensure incident_playbooks table exists for deduplicated playbooks."""
        with self.conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS incident_playbooks (
                    id SERIAL PRIMARY KEY,
                    incident_id VARCHAR(100) UNIQUE NOT NULL,
                    event_count INTEGER DEFAULT 1,
                    mitigation_status VARCHAR(50) DEFAULT 'pending',
                    remediation_steps JSONB,
                    analyst_guidance TEXT,
                    linked_fingerprints JSONB,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """)
            LOGGER.info("Ensured incident_playbooks table exists")
    
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

    def store_final_intelligence(self, fingerprint_id: int, mitre_data: dict, risk_data: dict, playbook_data: dict, event_count: int = 1):
        """STEP 8 - STORE FINAL INTELLIGENCE with deduplication"""
        with self.conn.cursor() as cur:
            # Update fingerprint to be a known attack
            cur.execute(
                "UPDATE fingerprints SET known_attack = TRUE, risk_level = %s, mitre_technique_id = %s, match_count = match_count + %s WHERE id = %s",
                (risk_data.get('level'), mitre_data.get('technique_id'), event_count, fingerprint_id)
            )

            # Check if MITRE mapping exists for this fingerprint
            cur.execute(
                "SELECT id FROM mitre_mappings WHERE fingerprint_id = %s",
                (fingerprint_id,)
            )
            existing_mitre = cur.fetchone()
            
            # Store MITRE mappings - truncate tactic to fit in VARCHAR(64)
            tactic = mitre_data.get('tactic', '')
            if len(tactic) > 64:
                tactic = tactic[:61] + "..."
            
            if existing_mitre:
                # Update existing MITRE mapping
                cur.execute(
                    "UPDATE mitre_mappings SET confidence = %s WHERE fingerprint_id = %s",
                    (mitre_data.get('confidence'), fingerprint_id)
                )
            else:
                # Insert new MITRE mapping
                cur.execute(
                    "INSERT INTO mitre_mappings (fingerprint_id, technique_id, tactic, confidence) VALUES (%s, %s, %s, %s)",
                    (fingerprint_id, mitre_data.get('technique_id'), tactic, mitre_data.get('confidence'))
                )

            # Check if risk score exists for this fingerprint
            cur.execute(
                "SELECT id FROM risk_scores WHERE fingerprint_id = %s",
                (fingerprint_id,)
            )
            existing_risk = cur.fetchone()
            
            if existing_risk:
                # Update existing risk score (use higher score)
                cur.execute(
                    "UPDATE risk_scores SET final_risk_score = GREATEST(final_risk_score, %s) WHERE fingerprint_id = %s",
                    (risk_data.get('final_risk_score'), fingerprint_id)
                )
            else:
                # Insert new risk score
                cur.execute(
                    "INSERT INTO risk_scores (fingerprint_id, final_risk_score) VALUES (%s, %s)",
                    (fingerprint_id, risk_data.get('final_risk_score'))
                )

            # Check if playbook exists for this fingerprint
            cur.execute(
                "SELECT id FROM playbooks WHERE fingerprint_id = %s",
                (fingerprint_id,)
            )
            existing_playbook = cur.fetchone()
            
            # Truncate analyst_guidance if too long
            analyst_guidance = playbook_data.get('analyst_guidance', '')
            if len(analyst_guidance) > 500:
                analyst_guidance = analyst_guidance[:497] + "..."
            
            if existing_playbook:
                # Update existing playbook instead of creating duplicate
                # Append event count and update timestamp
                existing_guidance = ""
                cur.execute(
                    "SELECT analyst_guidance FROM playbooks WHERE fingerprint_id = %s",
                    (fingerprint_id,)
                )
                row = cur.fetchone()
                if row:
                    existing_guidance = row[0] or ""
                
                # Update with new aggregated data but keep existing guidance
                cur.execute(
                    """UPDATE playbooks SET 
                       remediation_steps = %s,
                       updated_at = NOW()
                       WHERE fingerprint_id = %s""",
                    (json.dumps(playbook_data.get('remediation_steps')), fingerprint_id)
                )
                LOGGER.info(f"fingerprint_id={fingerprint_id} playbook UPDATED (deduplicated)")
            else:
                # Insert new playbook only if none exists
                cur.execute(
                    "INSERT INTO playbooks (fingerprint_id, remediation_steps, analyst_guidance) VALUES (%s, %s, %s)",
                    (fingerprint_id, json.dumps(playbook_data.get('remediation_steps')), analyst_guidance)
                )
                LOGGER.info(f"fingerprint_id={fingerprint_id} playbook CREATED (new)")

    def store_incident_playbook(self, incident_id: str, event_count: int, mitre_data: dict, 
                                  risk_data: dict, playbook_data: dict, linked_fingerprints: List[int]):
        """Store or update playbook per incident (deduplicated)."""
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT id, event_count, linked_fingerprints FROM incident_playbooks WHERE incident_id = %s",
                (incident_id,)
            )
            existing = cur.fetchone()
            
            remediation_steps = json.dumps(playbook_data.get('remediation_steps', []))
            analyst_guidance = playbook_data.get('analyst_guidance', '')[:500] if playbook_data.get('analyst_guidance') else ''
            incident_summary = playbook_data.get('incident_summary', '')[:1000] if playbook_data.get('incident_summary') else ''
            linked_fp_json = json.dumps(linked_fingerprints)
            
            if existing:
                old_count = existing[1]
                new_count = old_count + event_count
                
                existing_fps_data = existing[2] if len(existing) > 2 else None
                if isinstance(existing_fps_data, str):
                    existing_fps = set(json.loads(existing_fps_data))
                elif isinstance(existing_fps_data, list):
                    existing_fps = set(existing_fps_data)
                else:
                    existing_fps = set()
                    
                merged_fps = list(existing_fps.union(set(linked_fingerprints)))
                
                cur.execute("""
                    UPDATE incident_playbooks SET 
                        event_count = %s,
                        mitigation_status = CASE 
                            WHEN %s > 10 THEN 'escalated'
                            WHEN %s > 5 THEN 'investigating'
                            ELSE 'pending'
                        END,
                        updated_at = NOW(),
                        linked_fingerprints = %s,
                        analyst_guidance = COALESCE(analyst_guidance, %s),
                        incident_summary = COALESCE(incident_summary, %s)
                    WHERE incident_id = %s
                """, (new_count, new_count, new_count, json.dumps(merged_fps), analyst_guidance, incident_summary, incident_id))
                LOGGER.info(f"incident_id={incident_id} incident_playbook UPDATED (event_count: {old_count} -> {new_count})")
            else:
                status = 'escalated' if event_count > 10 else 'investigating' if event_count > 5 else 'pending'
                cur.execute("""
                    INSERT INTO incident_playbooks (
                        incident_id, event_count, mitigation_status, 
                        remediation_steps, analyst_guidance, incident_summary, linked_fingerprints
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (incident_id, event_count, status, remediation_steps, analyst_guidance, incident_summary, linked_fp_json))
                LOGGER.info(f"incident_id={incident_id} incident_playbook CREATED (event_count: {event_count})")

    def get_incident_playbook(self, incident_id: str) -> Optional[Dict]:
        """Get playbook for an incident."""
        with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM incident_playbooks WHERE incident_id = %s",
                (incident_id,)
            )
            return cur.fetchone()

    def close(self):
        self.conn.close()
