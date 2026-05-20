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
    """Get detailed incident graph with nodes and edges."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Get incident details
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
        
        # Get correlated events for this incident
        cur.execute("""
            SELECT event_id, event_timestamp, correlation_type, 
                   entity_type, entity_value
            FROM incident_events
            WHERE incident_id = %s
            ORDER BY event_timestamp
        """, (incident_id,))
        events = cur.fetchall()
        
        return {
            "incident": incident,
            "correlated_events": events,
            "graph": incident.get("graph_data", {"nodes": [], "edges": []}),
            "timeline": incident.get("timeline", []),
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

@app.get("/risk-summary")
def get_risk_summary(conn = Depends(get_db)):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute("SELECT risk_level, count(*) as count FROM fingerprints GROUP BY risk_level")
        return cur.fetchall()

@app.get("/attack-chains")
def get_attack_chains():
    # Will be hydrated when correlation engine graph is stored
    return []
