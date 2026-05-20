from fastapi import FastAPI, Depends, HTTPException
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Cyber Intelligence API")

# Enable CORS for Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    conn = psycopg2.connect(
        dbname=os.getenv("POSTGRES_DB", "cyber_intelligence"),
        user=os.getenv("POSTGRES_USER", "admin"),
        password=os.getenv("POSTGRES_PASSWORD", "adminpassword"),
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=os.getenv("POSTGRES_PORT", "5432")
    )
    try:
        yield conn
    finally:
        conn.close()

@app.get("/alerts")
def get_alerts(conn = Depends(get_db)):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT id, fingerprint_hash, event_type, first_seen, last_seen, match_count, risk_level FROM fingerprints ORDER BY last_seen DESC LIMIT 50")
        return cur.fetchall()

@app.get("/incidents")
def get_incidents(conn = Depends(get_db)):
    """Get all correlated incidents from the correlation engine."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT 
                incident_id, severity, confidence_score, attack_chain_stage,
                created_at, updated_at, status, linked_entities,
                array_length(related_event_ids, 1) as event_count
            FROM incidents 
            ORDER BY created_at DESC 
            LIMIT 100
        """)
        return cur.fetchall()


@app.get("/incident-graph/{incident_id}")
def get_incident_graph(incident_id: str, conn = Depends(get_db)):
    """Get detailed incident graph with meaningful attack chain visualization."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT incident_id, severity, confidence_score, attack_chain_stage,
                   created_at, description, graph_data, timeline, 
                   linked_entities, related_event_ids
            FROM incidents 
            WHERE incident_id = %s
        """, (incident_id,))
        incident = cur.fetchone()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        nodes = []
        edges = []
        entity_map = {}
        
        try:
            linked_entities = incident.get('linked_entities') or {}
            if isinstance(linked_entities, str):
                import json
                linked_entities = json.loads(linked_entities)
        except:
            linked_entities = {}
        
        src_ips = linked_entities.get('src_ips', []) if linked_entities else []
        dst_ips = linked_entities.get('dst_ips', []) if linked_entities else []
        usernames = linked_entities.get('usernames', []) if linked_entities else []
        hostnames = linked_entities.get('hostnames', []) if linked_entities else []
        processes = linked_entities.get('processes', []) if linked_entities else []
        
        nodes.append({
            "id": f"incident_{incident_id}",
            "label": incident_id,
            "type": "incident",
            "severity": incident.get('severity'),
            "attack_stage": incident.get('attack_chain_stage'),
            "metadata": {
                "confidence": incident.get('confidence_score'),
                "event_count": len(incident.get('related_event_ids', [])),
                "created_at": str(incident.get('created_at', ''))
            }
        })
        
        for idx, ip in enumerate(src_ips[:3]):
            node_key = f"src_ip_{ip}"
            if node_key not in entity_map:
                entity_map[node_key] = f"attacker_{idx}"
                nodes.append({
                    "id": f"attacker_{idx}",
                    "label": ip,
                    "type": "source_ip",
                    "severity": "high",
                    "metadata": {"role": "attacker", "ip": ip}
                })
            edges.append({
                "from": f"attacker_{idx}",
                "to": f"incident_{incident_id}",
                "type": "attack_origin",
                "label": "attacking"
            })
        
        for idx, ip in enumerate(dst_ips[:3]):
            node_key = f"dst_ip_{ip}"
            if node_key not in entity_map:
                entity_map[node_key] = f"target_{idx}"
                nodes.append({
                    "id": f"target_{idx}",
                    "label": ip,
                    "type": "destination_ip",
                    "severity": incident.get('severity'),
                    "metadata": {"role": "target", "ip": ip}
                })
            edges.append({
                "from": f"incident_{incident_id}",
                "to": f"target_{idx}",
                "type": "target",
                "label": "target"
            })
        
        for idx, user in enumerate(usernames[:3]):
            node_key = f"user_{user}"
            if node_key not in entity_map:
                entity_map[node_key] = f"user_{idx}"
                nodes.append({
                    "id": f"user_{idx}",
                    "label": user,
                    "type": "user",
                    "severity": "high",
                    "metadata": {"role": "compromised_account", "username": user}
                })
            edges.append({
                "from": f"incident_{incident_id}",
                "to": f"user_{idx}",
                "type": "credential_access",
                "label": "compromised"
            })
        
        for idx, hostname in enumerate(hostnames[:3]):
            node_key = f"host_{hostname}"
            if node_key not in entity_map:
                entity_map[node_key] = f"host_{idx}"
                nodes.append({
                    "id": f"host_{idx}",
                    "label": hostname,
                    "type": "hostname",
                    "severity": incident.get('severity'),
                    "metadata": {"role": "affected_system", "hostname": hostname}
                })
            edges.append({
                "from": f"incident_{incident_id}",
                "to": f"host_{idx}",
                "type": "affects",
                "label": "compromised"
            })
        
        for idx, process in enumerate(processes[:3]):
            node_key = f"process_{process}"
            if node_key not in entity_map:
                entity_map[node_key] = f"process_{idx}"
                nodes.append({
                    "id": f"process_{idx}",
                    "label": process,
                    "type": "process",
                    "severity": "medium",
                    "metadata": {"role": "suspicious_process", "process": process}
                })
            edges.append({
                "from": f"host_{idx}" if idx < len(hostnames) else f"incident_{incident_id}",
                "to": f"process_{idx}",
                "type": "execution",
                "label": "spawned"
            })
        
        stage = incident.get('attack_chain_stage', 'Unknown')
        stages = ['Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 
                  'Privilege Escalation', 'Credential Access', 'Defense Evasion', 
                  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control', 'Impact']
        
        if stage in stages:
            stage_idx = stages.index(stage)
            for i in range(stage_idx + 1):
                nodes.append({
                    "id": f"stage_{i}",
                    "label": stages[i],
                    "type": "mitre_stage",
                    "severity": "low",
                    "metadata": {"tactic": stages[i], "completed": i < stage_idx}
                })
                if i > 0:
                    edges.append({
                        "from": f"stage_{i-1}",
                        "to": f"stage_{i}",
                        "type": "attack_progression",
                        "label": "progression"
                    })
        
        timeline = []
        related_ids = incident.get('related_event_ids', [])
        for idx, evt_id in enumerate(related_ids[:10]):
            timeline.append({
                "event_id": evt_id,
                "timestamp": str(incident.get('created_at', '')),
                "type": "related_event",
                "sequence": idx + 1
            })
        
        return {
            "incident": {
                "incident_id": incident.get('incident_id'),
                "severity": incident.get('severity'),
                "confidence_score": incident.get('confidence_score'),
                "attack_chain_stage": incident.get('attack_chain_stage'),
                "created_at": str(incident.get('created_at', '')),
            },
            "nodes": nodes,
            "edges": edges,
            "entity_count": {
                "source_ips": len(src_ips),
                "destination_ips": len(dst_ips),
                "usernames": len(usernames),
                "hostnames": len(hostnames),
                "processes": len(processes),
            },
            "timeline": timeline,
        }


@app.get("/incident-timeline")
def get_incident_timeline(conn = Depends(get_db)):
    """Get all incidents with timeline for frontend visualization."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT 
                incident_id, severity, attack_chain_stage,
                created_at, timeline, related_event_ids
            FROM incidents 
            WHERE timeline IS NOT NULL
            ORDER BY created_at DESC 
            LIMIT 50
        """)
        return cur.fetchall()


@app.get("/incident-stats")
def get_incident_stats(conn = Depends(get_db)):
    """Get incident statistics for dashboard."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT 
                COUNT(*) as total_incidents,
                COUNT(CASE WHEN status = 'active' THEN 1 END) as active_incidents,
                COUNT(CASE WHEN severity = 'critical' THEN 1 END) as critical,
                COUNT(CASE WHEN severity = 'high' THEN 1 END) as high,
                COUNT(CASE WHEN severity = 'medium' THEN 1 END) as medium,
                COUNT(CASE WHEN severity = 'low' THEN 1 END) as low,
                COUNT(DISTINCT attack_chain_stage) as unique_stages
            FROM incidents
        """)
        stats = cur.fetchone()
        
        # Get stage distribution
        cur.execute("""
            SELECT attack_chain_stage, COUNT(*) as count
            FROM incidents
            WHERE attack_chain_stage IS NOT NULL
            GROUP BY attack_chain_stage
            ORDER BY count DESC
        """)
        stages = cur.fetchall()
        
        return {
            "total": stats["total_incidents"],
            "active": stats["active_incidents"],
            "by_severity": {
                "critical": stats["critical"],
                "high": stats["high"],
                "medium": stats["medium"],
                "low": stats["low"],
            },
            "by_stage": stages,
        }

@app.get("/mitre")
def get_mitre_mappings(conn = Depends(get_db)):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT m.*, f.fingerprint_string FROM mitre_mappings m JOIN fingerprints f ON m.fingerprint_id = f.id")
        return cur.fetchall()

@app.get("/playbooks")
def get_playbooks(conn = Depends(get_db)):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT p.*, f.risk_level FROM playbooks p JOIN fingerprints f ON p.fingerprint_id = f.id")
        return cur.fetchall()

@app.get("/incident-playbooks")
def get_incident_playbooks(conn = Depends(get_db)):
    """Get deduplicated playbooks per incident (new aggregated endpoint)."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT ip.*, i.severity, i.attack_chain_stage, i.confidence_score
            FROM incident_playbooks ip
            JOIN incidents i ON ip.incident_id = i.incident_id
            ORDER BY ip.event_count DESC, ip.updated_at DESC
            LIMIT 100
        """)
        return cur.fetchall()

@app.get("/incident-playbook/{incident_id}")
def get_incident_playbook_detail(incident_id: str, conn = Depends(get_db)):
    """Get detailed playbook for specific incident."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("""
            SELECT ip.*, i.severity, i.attack_chain_stage, i.confidence_score, 
                   i.linked_entities, i.related_event_ids
            FROM incident_playbooks ip
            JOIN incidents i ON ip.incident_id = i.incident_id
            WHERE ip.incident_id = %s
        """, (incident_id,))
        return cur.fetchone()

@app.get("/risk-summary")
def get_risk_summary(conn = Depends(get_db)):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT risk_level, count(*) as count FROM fingerprints GROUP BY risk_level")
        return cur.fetchall()

@app.get("/attack-chains")
def get_attack_chains():
    # Will be hydrated when correlation engine graph is stored
    return []
